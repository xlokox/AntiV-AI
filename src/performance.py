"""
Performance Optimization for AntiV-AI
Implements Redis caching and parallel processing for enhanced performance
"""

import os
import json
import asyncio
import logging
import time
import hashlib
from typing import Dict, List, Optional, Any, Callable, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import pickle

# Redis dependencies (optional)
try:
    import redis
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Performance configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
DEFAULT_CACHE_TTL = int(os.getenv('CACHE_TTL', '3600'))  # 1 hour
MAX_WORKERS = int(os.getenv('MAX_WORKERS', '4'))
THREAD_POOL_SIZE = int(os.getenv('THREAD_POOL_SIZE', '8'))

@dataclass
class CacheMetrics:
    """Cache performance metrics"""
    total_requests: int
    cache_hits: int
    cache_misses: int
    hit_rate: float
    average_response_time: float
    total_cached_items: int
    cache_size_bytes: int
    last_cleanup: Optional[str]

class RedisCache:
    """Redis-based caching system for performance optimization"""
    
    def __init__(self, redis_url: str = REDIS_URL, default_ttl: int = DEFAULT_CACHE_TTL):
        """Initialize Redis cache"""
        self.logger = logging.getLogger(__name__)
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self.redis_client = None
        self.async_redis_client = None
        
        # Metrics
        self.metrics = CacheMetrics(
            total_requests=0,
            cache_hits=0,
            cache_misses=0,
            hit_rate=0.0,
            average_response_time=0.0,
            total_cached_items=0,
            cache_size_bytes=0,
            last_cleanup=None
        )
        
        # Fallback in-memory cache if Redis is not available
        self.memory_cache = {}
        self.memory_cache_ttl = {}
        
        # Initialize Redis connection
        self._init_redis()
    
    def _init_redis(self):
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            self.logger.warning("Redis not available, using in-memory cache fallback")
            return
        
        try:
            # Synchronous Redis client
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis cache initialized successfully")
            
        except Exception as e:
            self.logger.warning(f"Redis connection failed, using fallback: {str(e)}")
            self.redis_client = None
    
    async def _init_async_redis(self):
        """Initialize async Redis connection"""
        if not REDIS_AVAILABLE or not self.redis_client:
            return
        
        try:
            self.async_redis_client = aioredis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5
            )
            
            # Test connection
            await self.async_redis_client.ping()
            
        except Exception as e:
            self.logger.warning(f"Async Redis connection failed: {str(e)}")
            self.async_redis_client = None
    
    def _generate_cache_key(self, prefix: str, *args, **kwargs) -> str:
        """Generate cache key from arguments"""
        # Create a deterministic key from arguments
        key_data = {
            'args': args,
            'kwargs': sorted(kwargs.items()) if kwargs else {}
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        
        return f"antiv:{prefix}:{key_hash}"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache (synchronous)"""
        start_time = time.time()
        self.metrics.total_requests += 1
        
        try:
            if self.redis_client:
                # Try Redis first
                value = self.redis_client.get(key)
                if value is not None:
                    self.metrics.cache_hits += 1
                    self._update_response_time(time.time() - start_time)
                    return pickle.loads(value.encode('latin1'))
            
            # Fallback to memory cache
            if key in self.memory_cache:
                # Check TTL
                if key in self.memory_cache_ttl:
                    if time.time() > self.memory_cache_ttl[key]:
                        # Expired
                        del self.memory_cache[key]
                        del self.memory_cache_ttl[key]
                    else:
                        self.metrics.cache_hits += 1
                        self._update_response_time(time.time() - start_time)
                        return self.memory_cache[key]
            
            # Cache miss
            self.metrics.cache_misses += 1
            self._update_response_time(time.time() - start_time)
            return None
            
        except Exception as e:
            self.logger.error(f"Cache get error: {str(e)}")
            self.metrics.cache_misses += 1
            return None
    
    async def aget(self, key: str) -> Optional[Any]:
        """Get value from cache (asynchronous)"""
        start_time = time.time()
        self.metrics.total_requests += 1
        
        try:
            if not self.async_redis_client:
                await self._init_async_redis()
            
            if self.async_redis_client:
                # Try async Redis
                value = await self.async_redis_client.get(key)
                if value is not None:
                    self.metrics.cache_hits += 1
                    self._update_response_time(time.time() - start_time)
                    return pickle.loads(value.encode('latin1'))
            
            # Fallback to synchronous get
            return self.get(key)
            
        except Exception as e:
            self.logger.error(f"Async cache get error: {str(e)}")
            return self.get(key)  # Fallback to sync
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache (synchronous)"""
        if ttl is None:
            ttl = self.default_ttl
        
        try:
            serialized_value = pickle.dumps(value).decode('latin1')
            
            if self.redis_client:
                # Set in Redis
                self.redis_client.setex(key, ttl, serialized_value)
            else:
                # Set in memory cache
                self.memory_cache[key] = value
                self.memory_cache_ttl[key] = time.time() + ttl
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cache set error: {str(e)}")
            return False
    
    async def aset(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache (asynchronous)"""
        if ttl is None:
            ttl = self.default_ttl
        
        try:
            if not self.async_redis_client:
                await self._init_async_redis()
            
            if self.async_redis_client:
                serialized_value = pickle.dumps(value).decode('latin1')
                await self.async_redis_client.setex(key, ttl, serialized_value)
                return True
            else:
                # Fallback to synchronous set
                return self.set(key, value, ttl)
                
        except Exception as e:
            self.logger.error(f"Async cache set error: {str(e)}")
            return self.set(key, value, ttl)  # Fallback to sync
    
    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        try:
            if self.redis_client:
                self.redis_client.delete(key)
            
            # Also remove from memory cache
            self.memory_cache.pop(key, None)
            self.memory_cache_ttl.pop(key, None)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cache delete error: {str(e)}")
            return False
    
    def clear(self) -> bool:
        """Clear all cache entries"""
        try:
            if self.redis_client:
                # Clear only AntiV-AI keys
                keys = self.redis_client.keys("antiv:*")
                if keys:
                    self.redis_client.delete(*keys)
            
            # Clear memory cache
            self.memory_cache.clear()
            self.memory_cache_ttl.clear()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cache clear error: {str(e)}")
            return False
    
    def _update_response_time(self, response_time: float):
        """Update average response time metric"""
        if self.metrics.average_response_time == 0.0:
            self.metrics.average_response_time = response_time
        else:
            # Exponential moving average
            self.metrics.average_response_time = (
                self.metrics.average_response_time * 0.9 + response_time * 0.1
            )
    
    def get_metrics(self) -> Dict:
        """Get cache performance metrics"""
        try:
            # Update hit rate
            if self.metrics.total_requests > 0:
                self.metrics.hit_rate = self.metrics.cache_hits / self.metrics.total_requests
            
            # Get cache size info
            if self.redis_client:
                try:
                    info = self.redis_client.info('memory')
                    self.metrics.cache_size_bytes = info.get('used_memory', 0)
                    
                    # Count AntiV-AI keys
                    keys = self.redis_client.keys("antiv:*")
                    self.metrics.total_cached_items = len(keys)
                except:
                    pass
            else:
                # Memory cache size
                self.metrics.total_cached_items = len(self.memory_cache)
                self.metrics.cache_size_bytes = sum(
                    len(str(k)) + len(str(v)) for k, v in self.memory_cache.items()
                )
            
            return asdict(self.metrics)
            
        except Exception as e:
            self.logger.error(f"Error getting cache metrics: {str(e)}")
            return {}
    
    def cache_decorator(self, prefix: str, ttl: Optional[int] = None):
        """Decorator for caching function results"""
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_cache_key(prefix, *args, **kwargs)
                
                # Try to get from cache
                cached_result = self.get(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function and cache result
                result = func(*args, **kwargs)
                self.set(cache_key, result, ttl)
                
                return result
            
            async def async_wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_cache_key(prefix, *args, **kwargs)
                
                # Try to get from cache
                cached_result = await self.aget(cache_key)
                if cached_result is not None:
                    return cached_result
                
                # Execute function and cache result
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                await self.aset(cache_key, result, ttl)
                
                return result
            
            # Return appropriate wrapper based on function type
            if asyncio.iscoroutinefunction(func):
                return async_wrapper
            else:
                return wrapper
        
        return decorator

class ParallelProcessor:
    """Parallel processing helper for CPU-intensive tasks"""
    
    def __init__(self, max_workers: int = MAX_WORKERS):
        """Initialize parallel processor"""
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers
        self.thread_pool = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)
    
    def process_parallel(self, func: Callable, items: List[Any], *args, **kwargs) -> List[Any]:
        """
        Process items in parallel using thread pool
        
        Args:
            func: Function to apply to each item
            items: List of items to process
            *args, **kwargs: Additional arguments for the function
            
        Returns:
            List of results in the same order as input items
        """
        if not items:
            return []
        
        try:
            # Submit all tasks
            future_to_index = {}
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                for i, item in enumerate(items):
                    future = executor.submit(func, item, *args, **kwargs)
                    future_to_index[future] = i
                
                # Collect results in order
                results = [None] * len(items)
                for future in as_completed(future_to_index):
                    index = future_to_index[future]
                    try:
                        results[index] = future.result()
                    except Exception as e:
                        self.logger.error(f"Parallel processing error for item {index}: {str(e)}")
                        results[index] = None
                
                return results
                
        except Exception as e:
            self.logger.error(f"Parallel processing failed: {str(e)}")
            # Fallback to sequential processing
            return [func(item, *args, **kwargs) for item in items]
    
    async def process_parallel_async(self, func: Callable, items: List[Any], *args, **kwargs) -> List[Any]:
        """
        Process items in parallel using asyncio
        
        Args:
            func: Async function to apply to each item
            items: List of items to process
            *args, **kwargs: Additional arguments for the function
            
        Returns:
            List of results in the same order as input items
        """
        if not items:
            return []
        
        try:
            # Create tasks
            tasks = []
            for item in items:
                if asyncio.iscoroutinefunction(func):
                    task = func(item, *args, **kwargs)
                else:
                    # Run sync function in thread pool
                    task = asyncio.get_event_loop().run_in_executor(
                        self.thread_pool, func, item, *args, **kwargs
                    )
                tasks.append(task)
            
            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Handle exceptions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.error(f"Async parallel processing error for item {i}: {str(result)}")
                    results[i] = None
            
            return results
            
        except Exception as e:
            self.logger.error(f"Async parallel processing failed: {str(e)}")
            # Fallback to sequential processing
            results = []
            for item in items:
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(item, *args, **kwargs)
                    else:
                        result = func(item, *args, **kwargs)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Sequential fallback error: {str(e)}")
                    results.append(None)
            
            return results
    
    def batch_process(self, func: Callable, items: List[Any], batch_size: int = 10, *args, **kwargs) -> List[Any]:
        """
        Process items in batches to control memory usage
        
        Args:
            func: Function to apply to each batch
            items: List of items to process
            batch_size: Size of each batch
            *args, **kwargs: Additional arguments for the function
            
        Returns:
            Flattened list of results
        """
        if not items:
            return []
        
        results = []
        
        try:
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_results = self.process_parallel(func, batch, *args, **kwargs)
                results.extend(batch_results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Batch processing failed: {str(e)}")
            return []
    
    def __del__(self):
        """Cleanup thread pool"""
        try:
            self.thread_pool.shutdown(wait=True)
        except:
            pass

class ParallelScanner:
    """Parallel file scanning helper using ThreadPoolExecutor"""

    def __init__(self, max_workers: int = MAX_WORKERS):
        """Initialize parallel scanner"""
        self.logger = logging.getLogger(__name__)
        self.max_workers = max_workers
        self.thread_pool = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)

        # Statistics
        self.stats = {
            'total_scans': 0,
            'parallel_scans': 0,
            'sequential_scans': 0,
            'average_scan_time': 0.0,
            'total_scan_time': 0.0
        }

    def scan_files_parallel(self, scan_func: Callable, file_paths: List[str], *args, **kwargs) -> List[Any]:
        """
        Scan multiple files in parallel

        Args:
            scan_func: Function to apply to each file
            file_paths: List of file paths to scan
            *args, **kwargs: Additional arguments for the scan function

        Returns:
            List of scan results in the same order as input files
        """
        if not file_paths:
            return []

        start_time = time.time()
        self.stats['total_scans'] += len(file_paths)

        try:
            if len(file_paths) == 1:
                # Single file - no need for parallelization
                self.stats['sequential_scans'] += 1
                result = [scan_func(file_paths[0], *args, **kwargs)]
            else:
                # Multiple files - use parallel processing
                self.stats['parallel_scans'] += len(file_paths)
                result = self._process_parallel(scan_func, file_paths, *args, **kwargs)

            # Update timing statistics
            scan_time = time.time() - start_time
            self.stats['total_scan_time'] += scan_time
            if self.stats['total_scans'] > 0:
                self.stats['average_scan_time'] = self.stats['total_scan_time'] / self.stats['total_scans']

            return result

        except Exception as e:
            self.logger.error(f"Parallel scanning failed: {str(e)}")
            # Fallback to sequential processing
            self.stats['sequential_scans'] += len(file_paths)
            return [scan_func(file_path, *args, **kwargs) for file_path in file_paths]

    def _process_parallel(self, func: Callable, items: List[Any], *args, **kwargs) -> List[Any]:
        """Process items in parallel using thread pool"""
        if not items:
            return []

        try:
            # Submit all tasks
            future_to_index = {}
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                for i, item in enumerate(items):
                    future = executor.submit(func, item, *args, **kwargs)
                    future_to_index[future] = i

                # Collect results in order
                results = [None] * len(items)
                for future in as_completed(future_to_index):
                    index = future_to_index[future]
                    try:
                        results[index] = future.result()
                    except Exception as e:
                        self.logger.error(f"Parallel processing error for item {index}: {str(e)}")
                        results[index] = None

                return results

        except Exception as e:
            self.logger.error(f"Parallel processing failed: {str(e)}")
            # Fallback to sequential processing
            return [func(item, *args, **kwargs) for item in items]

    async def scan_files_async(self, scan_func: Callable, file_paths: List[str], *args, **kwargs) -> List[Any]:
        """
        Scan multiple files asynchronously

        Args:
            scan_func: Async function to apply to each file
            file_paths: List of file paths to scan
            *args, **kwargs: Additional arguments for the scan function

        Returns:
            List of scan results in the same order as input files
        """
        if not file_paths:
            return []

        start_time = time.time()
        self.stats['total_scans'] += len(file_paths)

        try:
            # Create tasks
            tasks = []
            for file_path in file_paths:
                if asyncio.iscoroutinefunction(scan_func):
                    task = scan_func(file_path, *args, **kwargs)
                else:
                    # Run sync function in thread pool
                    task = asyncio.get_event_loop().run_in_executor(
                        self.thread_pool, scan_func, file_path, *args, **kwargs
                    )
                tasks.append(task)

            # Execute all tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Handle exceptions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.error(f"Async scanning error for file {i}: {str(result)}")
                    results[i] = None

            # Update timing statistics
            scan_time = time.time() - start_time
            self.stats['total_scan_time'] += scan_time
            if self.stats['total_scans'] > 0:
                self.stats['average_scan_time'] = self.stats['total_scan_time'] / self.stats['total_scans']

            return results

        except Exception as e:
            self.logger.error(f"Async scanning failed: {str(e)}")
            # Fallback to sequential processing
            results = []
            for file_path in file_paths:
                try:
                    if asyncio.iscoroutinefunction(scan_func):
                        result = await scan_func(file_path, *args, **kwargs)
                    else:
                        result = scan_func(file_path, *args, **kwargs)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Sequential fallback error: {str(e)}")
                    results.append(None)

            return results

    def get_stats(self) -> Dict:
        """Get parallel scanning statistics"""
        return self.stats.copy()

    def __del__(self):
        """Cleanup thread pool"""
        try:
            self.thread_pool.shutdown(wait=True)
        except:
            pass

# Global instances
redis_cache = RedisCache()
parallel_processor = ParallelProcessor()
parallel_scanner = ParallelScanner()

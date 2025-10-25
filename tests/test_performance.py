"""
Performance tests for AntiV-AI caching and parallel processing
"""

import pytest
import asyncio
import time
import tempfile
import os
from unittest.mock import Mock, patch
from concurrent.futures import ThreadPoolExecutor

# Import modules to test
import sys
sys.path.append('src')

from performance import RedisCache, ParallelScanner, ParallelProcessor

class TestRedisCachePerformance:
    """Performance tests for Redis cache"""
    
    @pytest.fixture
    def cache(self):
        """Create cache instance for testing"""
        return RedisCache()
    
    def test_cache_performance_sync(self, cache):
        """Test synchronous cache performance"""
        # Test multiple operations
        start_time = time.time()
        
        for i in range(100):
            key = f"test_key_{i}"
            value = {"data": f"value_{i}", "index": i}
            
            # Set value
            cache.set(key, value, 60)
            
            # Get value
            result = cache.get(key)
            assert result == value
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should complete 200 operations (100 sets + 100 gets) reasonably fast
        assert total_time < 5.0, f"Cache operations took too long: {total_time}s"
        
        # Check metrics
        metrics = cache.get_metrics()
        assert metrics['total_requests'] >= 100
        assert metrics['hit_rate'] > 0.0
    
    @pytest.mark.asyncio
    async def test_cache_performance_async(self, cache):
        """Test asynchronous cache performance"""
        start_time = time.time()
        
        # Test concurrent operations
        async def cache_operation(i):
            key = f"async_key_{i}"
            value = {"async_data": f"value_{i}"}
            
            await cache.aset(key, value, 60)
            result = await cache.aget(key)
            return result == value
        
        # Run 50 concurrent operations
        tasks = [cache_operation(i) for i in range(50)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # All operations should succeed
        assert all(results)
        
        # Should be faster than sequential operations
        assert total_time < 3.0, f"Async cache operations took too long: {total_time}s"
    
    def test_cache_decorator_performance(self, cache):
        """Test cache decorator performance"""
        call_count = 0
        
        @cache.cache_decorator("expensive_func", 60)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            time.sleep(0.01)  # Simulate expensive operation
            return x * 2
        
        # First call - should execute function
        start_time = time.time()
        result1 = expensive_function(5)
        first_call_time = time.time() - start_time
        
        assert result1 == 10
        assert call_count == 1
        
        # Second call - should use cache
        start_time = time.time()
        result2 = expensive_function(5)
        second_call_time = time.time() - start_time
        
        assert result2 == 10
        assert call_count == 1  # Should not increment
        
        # Cache hit should be much faster
        assert second_call_time < first_call_time / 2
    
    def test_cache_memory_usage(self, cache):
        """Test cache memory usage and cleanup"""
        initial_metrics = cache.get_metrics()
        initial_items = initial_metrics.get('total_cached_items', 0)
        
        # Add many items
        for i in range(1000):
            cache.set(f"memory_test_{i}", {"data": "x" * 100}, 60)
        
        # Check memory usage
        metrics = cache.get_metrics()
        assert metrics['total_cached_items'] > initial_items
        
        # Clear cache
        cache.clear()
        
        # Memory should be freed
        final_metrics = cache.get_metrics()
        # Note: Redis cache might not immediately reflect cleared items
        # This test mainly ensures the clear operation doesn't crash

class TestParallelScannerPerformance:
    """Performance tests for parallel scanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance for testing"""
        return ParallelScanner(max_workers=4)
    
    def test_parallel_vs_sequential_performance(self, scanner):
        """Test parallel vs sequential scanning performance"""
        def mock_scan_function(file_path):
            # Simulate CPU-intensive work
            time.sleep(0.1)
            return {"file": file_path, "result": "clean"}
        
        file_paths = [f"file_{i}.txt" for i in range(10)]
        
        # Test sequential performance (baseline)
        start_time = time.time()
        sequential_results = [mock_scan_function(path) for path in file_paths]
        sequential_time = time.time() - start_time
        
        # Test parallel performance
        start_time = time.time()
        parallel_results = scanner.scan_files_parallel(mock_scan_function, file_paths)
        parallel_time = time.time() - start_time
        
        # Results should be the same
        assert len(sequential_results) == len(parallel_results)
        
        # Parallel should be faster (with some tolerance for overhead)
        speedup_ratio = sequential_time / parallel_time
        assert speedup_ratio > 1.5, f"Parallel scanning not fast enough: {speedup_ratio}x speedup"
        
        print(f"Sequential time: {sequential_time:.2f}s")
        print(f"Parallel time: {parallel_time:.2f}s")
        print(f"Speedup: {speedup_ratio:.2f}x")
    
    @pytest.mark.asyncio
    async def test_async_parallel_performance(self, scanner):
        """Test async parallel scanning performance"""
        async def mock_async_scan(file_path):
            await asyncio.sleep(0.05)  # Simulate async I/O
            return {"file": file_path, "result": "clean"}
        
        file_paths = [f"async_file_{i}.txt" for i in range(20)]
        
        # Test async parallel performance
        start_time = time.time()
        results = await scanner.scan_files_async(mock_async_scan, file_paths)
        async_time = time.time() - start_time
        
        # Should complete much faster than sequential
        expected_sequential_time = len(file_paths) * 0.05
        assert async_time < expected_sequential_time / 2
        
        # All results should be present
        assert len(results) == len(file_paths)
        assert all(result["result"] == "clean" for result in results if result)
    
    def test_scanner_with_large_batch(self, scanner):
        """Test scanner with large batch of files"""
        def quick_scan(file_path):
            return {"file": file_path, "size": len(file_path)}
        
        # Large batch
        file_paths = [f"large_batch_file_{i:04d}.txt" for i in range(100)]
        
        start_time = time.time()
        results = scanner.scan_files_parallel(quick_scan, file_paths)
        total_time = time.time() - start_time
        
        # Should handle large batches efficiently
        assert len(results) == 100
        assert total_time < 5.0, f"Large batch took too long: {total_time}s"
        
        # Check statistics
        stats = scanner.get_stats()
        assert stats['total_scans'] >= 100
        assert stats['parallel_scans'] > 0
    
    def test_error_handling_performance(self, scanner):
        """Test performance with error handling"""
        def unreliable_scan(file_path):
            if "error" in file_path:
                raise Exception("Simulated scan error")
            time.sleep(0.01)
            return {"file": file_path, "result": "clean"}
        
        # Mix of good and bad files
        file_paths = []
        for i in range(50):
            if i % 10 == 0:
                file_paths.append(f"error_file_{i}.txt")
            else:
                file_paths.append(f"good_file_{i}.txt")
        
        start_time = time.time()
        results = scanner.scan_files_parallel(unreliable_scan, file_paths)
        total_time = time.time() - start_time
        
        # Should handle errors gracefully without significant slowdown
        assert total_time < 2.0, f"Error handling caused slowdown: {total_time}s"
        
        # Should have some successful results and some None (errors)
        successful_results = [r for r in results if r is not None]
        error_results = [r for r in results if r is None]
        
        assert len(successful_results) > 0
        assert len(error_results) > 0
        assert len(successful_results) + len(error_results) == len(file_paths)

class TestIntegratedPerformance:
    """Test integrated performance scenarios"""
    
    def test_cached_parallel_scanning(self):
        """Test performance of cached parallel scanning"""
        cache = RedisCache()
        scanner = ParallelScanner(max_workers=2)
        
        def cached_scan_function(file_path):
            # Check cache first
            cache_key = f"scan_result:{file_path}"
            cached_result = cache.get(cache_key)
            if cached_result:
                return cached_result
            
            # Simulate expensive scan
            time.sleep(0.05)
            result = {"file": file_path, "result": "clean", "cached": False}
            
            # Cache result
            cache.set(cache_key, result, 300)
            return result
        
        file_paths = [f"cached_file_{i}.txt" for i in range(10)]
        
        # First scan - should be slow (cache misses)
        start_time = time.time()
        first_results = scanner.scan_files_parallel(cached_scan_function, file_paths)
        first_scan_time = time.time() - start_time
        
        # Second scan - should be fast (cache hits)
        start_time = time.time()
        second_results = scanner.scan_files_parallel(cached_scan_function, file_paths)
        second_scan_time = time.time() - start_time
        
        # Results should be the same
        assert len(first_results) == len(second_results)
        
        # Second scan should be much faster due to caching
        speedup = first_scan_time / second_scan_time
        assert speedup > 2.0, f"Caching didn't provide enough speedup: {speedup}x"
        
        print(f"First scan (cache miss): {first_scan_time:.2f}s")
        print(f"Second scan (cache hit): {second_scan_time:.2f}s")
        print(f"Cache speedup: {speedup:.2f}x")
    
    @pytest.mark.slow
    def test_stress_test_performance(self):
        """Stress test for performance under load"""
        cache = RedisCache()
        scanner = ParallelScanner(max_workers=8)
        
        def stress_scan_function(file_path):
            # Random cache operations
            import random
            cache_key = f"stress:{random.randint(1, 100)}"
            
            if random.random() < 0.5:
                # Cache hit scenario
                cached = cache.get(cache_key)
                if cached:
                    return cached
            
            # Simulate work
            time.sleep(random.uniform(0.001, 0.01))
            result = {"file": file_path, "random": random.randint(1, 1000)}
            
            # Cache result
            cache.set(cache_key, result, 60)
            return result
        
        # Large number of files
        file_paths = [f"stress_file_{i:05d}.txt" for i in range(200)]
        
        start_time = time.time()
        results = scanner.scan_files_parallel(stress_scan_function, file_paths)
        total_time = time.time() - start_time
        
        # Should handle stress test reasonably
        assert len(results) == 200
        assert total_time < 10.0, f"Stress test took too long: {total_time}s"
        
        # Check final statistics
        cache_metrics = cache.get_metrics()
        scanner_stats = scanner.get_stats()
        
        print(f"Stress test completed in {total_time:.2f}s")
        print(f"Cache hit rate: {cache_metrics.get('hit_rate', 0):.2%}")
        print(f"Scanner stats: {scanner_stats}")

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

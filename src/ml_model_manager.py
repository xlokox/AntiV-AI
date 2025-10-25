"""
ML Model Version Management for AntiV-AI
Handles model versioning, metadata tracking, and rollback capabilities
"""

import os
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import joblib
from dataclasses import dataclass, asdict

@dataclass
class ModelMetadata:
    """Model metadata structure"""
    version: str
    timestamp: str
    model_type: str  # 'behavioral_analysis', 'isolation_forest', 'ensemble'
    file_path: str
    metrics: Dict[str, float]
    training_samples: int
    feature_count: int
    algorithm: str
    parameters: Dict[str, Any]
    is_active: bool = False
    created_by: str = "system"
    notes: str = ""

class MLModelManager:
    """ML Model Version Management System"""
    
    def __init__(self, models_dir: str = "models", metadata_file: str = None):
        """
        Initialize ML Model Manager
        
        Args:
            models_dir: Directory containing model files
            metadata_file: Path to metadata JSON file
        """
        self.models_dir = Path(models_dir)
        self.models_dir.mkdir(exist_ok=True)
        
        self.metadata_file = Path(metadata_file) if metadata_file else self.models_dir / "metadata.json"
        self.logger = logging.getLogger(__name__)
        
        # Load existing metadata
        self.metadata = self._load_metadata()
        
        # Ensure metadata file exists
        self._save_metadata()
    
    def _load_metadata(self) -> Dict[str, Dict]:
        """Load model metadata from JSON file"""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    data = json.load(f)
                    
                # Convert to ModelMetadata objects
                metadata = {}
                for version, model_data in data.items():
                    for model_type, model_info in model_data.items():
                        key = f"{model_type}_{version}"
                        metadata[key] = ModelMetadata(**model_info)
                
                return metadata
            else:
                return {}
                
        except Exception as e:
            self.logger.error(f"Error loading metadata: {e}")
            return {}
    
    def _save_metadata(self):
        """Save model metadata to JSON file"""
        try:
            # Convert ModelMetadata objects to dict
            data = {}
            for key, model_metadata in self.metadata.items():
                version = model_metadata.version
                model_type = model_metadata.model_type
                
                if version not in data:
                    data[version] = {}
                
                data[version][model_type] = asdict(model_metadata)
            
            with open(self.metadata_file, 'w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
                
        except Exception as e:
            self.logger.error(f"Error saving metadata: {e}")
    
    def register_model(
        self,
        model_type: str,
        version: str,
        file_path: str,
        metrics: Dict[str, float],
        training_samples: int = 0,
        feature_count: int = 0,
        algorithm: str = "",
        parameters: Dict[str, Any] = None,
        created_by: str = "system",
        notes: str = ""
    ) -> bool:
        """
        Register a new model version
        
        Args:
            model_type: Type of model (behavioral_analysis, isolation_forest, ensemble)
            version: Version identifier (usually timestamp)
            file_path: Path to the model file
            metrics: Training metrics
            training_samples: Number of training samples used
            feature_count: Number of features
            algorithm: Algorithm name
            parameters: Model parameters
            created_by: Who created the model
            notes: Additional notes
            
        Returns:
            bool: Success status
        """
        try:
            # Validate model file exists
            if not Path(file_path).exists():
                self.logger.error(f"Model file not found: {file_path}")
                return False
            
            # Create metadata entry
            key = f"{model_type}_{version}"
            
            metadata = ModelMetadata(
                version=version,
                timestamp=datetime.now().isoformat(),
                model_type=model_type,
                file_path=str(file_path),
                metrics=metrics or {},
                training_samples=training_samples,
                feature_count=feature_count,
                algorithm=algorithm,
                parameters=parameters or {},
                is_active=False,
                created_by=created_by,
                notes=notes
            )
            
            self.metadata[key] = metadata
            self._save_metadata()
            
            self.logger.info(f"Registered model: {model_type} version {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error registering model: {e}")
            return False
    
    def get_latest_model(self, model_type: str) -> Optional[ModelMetadata]:
        """
        Get the latest version of a specific model type
        
        Args:
            model_type: Type of model to retrieve
            
        Returns:
            ModelMetadata or None if not found
        """
        try:
            # Find all versions of this model type
            model_versions = [
                metadata for key, metadata in self.metadata.items()
                if metadata.model_type == model_type
            ]
            
            if not model_versions:
                return None
            
            # Sort by timestamp (latest first)
            model_versions.sort(key=lambda x: x.timestamp, reverse=True)
            
            return model_versions[0]
            
        except Exception as e:
            self.logger.error(f"Error getting latest model: {e}")
            return None
    
    def get_active_model(self, model_type: str) -> Optional[ModelMetadata]:
        """
        Get the currently active model of a specific type
        
        Args:
            model_type: Type of model to retrieve
            
        Returns:
            ModelMetadata or None if not found
        """
        try:
            for metadata in self.metadata.values():
                if metadata.model_type == model_type and metadata.is_active:
                    return metadata
            
            # If no active model, return latest
            return self.get_latest_model(model_type)
            
        except Exception as e:
            self.logger.error(f"Error getting active model: {e}")
            return None
    
    def set_active_model(self, model_type: str, version: str) -> bool:
        """
        Set a specific model version as active
        
        Args:
            model_type: Type of model
            version: Version to activate
            
        Returns:
            bool: Success status
        """
        try:
            # Deactivate all models of this type
            for metadata in self.metadata.values():
                if metadata.model_type == model_type:
                    metadata.is_active = False
            
            # Activate the specified version
            key = f"{model_type}_{version}"
            if key in self.metadata:
                self.metadata[key].is_active = True
                self._save_metadata()
                
                self.logger.info(f"Activated model: {model_type} version {version}")
                return True
            else:
                self.logger.error(f"Model not found: {model_type} version {version}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting active model: {e}")
            return False
    
    def rollback_to(self, model_type: str, version: str) -> bool:
        """
        Rollback to a specific model version
        
        Args:
            model_type: Type of model
            version: Version to rollback to
            
        Returns:
            bool: Success status
        """
        try:
            key = f"{model_type}_{version}"
            
            if key not in self.metadata:
                self.logger.error(f"Model version not found: {model_type} version {version}")
                return False
            
            metadata = self.metadata[key]
            
            # Verify model file exists
            if not Path(metadata.file_path).exists():
                self.logger.error(f"Model file not found: {metadata.file_path}")
                return False
            
            # Create symlink to the rollback version
            latest_symlink = self.models_dir / f"{model_type}.pkl"
            
            # Remove existing symlink
            if latest_symlink.is_symlink():
                latest_symlink.unlink()
            elif latest_symlink.exists():
                # Backup existing file
                backup_path = latest_symlink.with_suffix('.pkl.backup')
                shutil.move(str(latest_symlink), str(backup_path))
            
            # Create new symlink
            relative_path = Path(metadata.file_path).name
            latest_symlink.symlink_to(relative_path)
            
            # Set as active
            self.set_active_model(model_type, version)
            
            self.logger.info(f"Rolled back to model: {model_type} version {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error rolling back model: {e}")
            return False
    
    def list_versions(self, model_type: str = None) -> List[ModelMetadata]:
        """
        List all model versions, optionally filtered by type
        
        Args:
            model_type: Optional model type filter
            
        Returns:
            List of ModelMetadata objects
        """
        try:
            versions = []
            
            for metadata in self.metadata.values():
                if model_type is None or metadata.model_type == model_type:
                    versions.append(metadata)
            
            # Sort by timestamp (latest first)
            versions.sort(key=lambda x: x.timestamp, reverse=True)
            
            return versions
            
        except Exception as e:
            self.logger.error(f"Error listing versions: {e}")
            return []
    
    def delete_version(self, model_type: str, version: str, force: bool = False) -> bool:
        """
        Delete a specific model version
        
        Args:
            model_type: Type of model
            version: Version to delete
            force: Force deletion even if active
            
        Returns:
            bool: Success status
        """
        try:
            key = f"{model_type}_{version}"
            
            if key not in self.metadata:
                self.logger.error(f"Model version not found: {model_type} version {version}")
                return False
            
            metadata = self.metadata[key]
            
            # Prevent deletion of active model unless forced
            if metadata.is_active and not force:
                self.logger.error(f"Cannot delete active model without force flag")
                return False
            
            # Delete model file
            model_file = Path(metadata.file_path)
            if model_file.exists():
                model_file.unlink()
            
            # Remove from metadata
            del self.metadata[key]
            self._save_metadata()
            
            self.logger.info(f"Deleted model: {model_type} version {version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting model version: {e}")
            return False
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get statistics about managed models"""
        try:
            stats = {
                'total_models': len(self.metadata),
                'model_types': {},
                'active_models': {},
                'latest_models': {},
                'storage_info': {}
            }
            
            # Count by model type
            for metadata in self.metadata.values():
                model_type = metadata.model_type
                
                if model_type not in stats['model_types']:
                    stats['model_types'][model_type] = 0
                stats['model_types'][model_type] += 1
                
                # Track active models
                if metadata.is_active:
                    stats['active_models'][model_type] = metadata.version
            
            # Get latest models
            for model_type in stats['model_types'].keys():
                latest = self.get_latest_model(model_type)
                if latest:
                    stats['latest_models'][model_type] = latest.version
            
            # Calculate storage usage
            total_size = 0
            for metadata in self.metadata.values():
                try:
                    file_path = Path(metadata.file_path)
                    if file_path.exists():
                        total_size += file_path.stat().st_size
                except:
                    pass
            
            stats['storage_info'] = {
                'total_size_bytes': total_size,
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'models_directory': str(self.models_dir),
                'metadata_file': str(self.metadata_file)
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting model stats: {e}")
            return {}
    
    def load_model(self, model_type: str, version: str = None) -> Optional[Any]:
        """
        Load a specific model version
        
        Args:
            model_type: Type of model to load
            version: Specific version (if None, loads active/latest)
            
        Returns:
            Loaded model object or None
        """
        try:
            if version:
                key = f"{model_type}_{version}"
                if key not in self.metadata:
                    return None
                metadata = self.metadata[key]
            else:
                metadata = self.get_active_model(model_type)
                if not metadata:
                    return None
            
            # Load model file
            model_path = Path(metadata.file_path)
            if not model_path.exists():
                self.logger.error(f"Model file not found: {model_path}")
                return None
            
            model = joblib.load(model_path)
            self.logger.info(f"Loaded model: {model_type} version {metadata.version}")
            
            return model
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return None
    
    def cleanup_old_versions(self, model_type: str, keep_count: int = 5) -> int:
        """
        Clean up old model versions, keeping only the most recent ones
        
        Args:
            model_type: Type of model to clean up
            keep_count: Number of versions to keep
            
        Returns:
            Number of versions deleted
        """
        try:
            versions = self.list_versions(model_type)
            
            if len(versions) <= keep_count:
                return 0
            
            # Keep the most recent versions and active model
            to_delete = []
            active_version = None
            
            # Find active version
            for version in versions:
                if version.is_active:
                    active_version = version.version
                    break
            
            # Mark versions for deletion (skip active and most recent)
            kept_count = 0
            for version in versions:
                if version.is_active:
                    continue  # Never delete active model
                
                if kept_count < keep_count:
                    kept_count += 1
                    continue
                
                to_delete.append(version)
            
            # Delete old versions
            deleted_count = 0
            for version in to_delete:
                if self.delete_version(version.model_type, version.version):
                    deleted_count += 1
            
            self.logger.info(f"Cleaned up {deleted_count} old versions of {model_type}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old versions: {e}")
            return 0

# Global instance
ml_model_manager = MLModelManager()

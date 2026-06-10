"""
Comprehensive tests for ML training pipeline components
"""

import pytest
import asyncio
import json
import tempfile
import shutil
import os
import numpy as np
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime

# Import modules to test
import sys
sys.path.append('src')

from ml_model_manager import MLModelManager, ModelMetadata
from ml_evaluation import MLEvaluationFramework
from scripts.train_models import MLTrainingPipeline

class TestMLTrainingPipeline:
    """Test ML training pipeline functionality"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def training_pipeline(self, temp_dir):
        """Create training pipeline instance for testing"""
        # Create temporary config
        config = {
            'machine_learning': {
                'models': {
                    'isolation_forest': {'contamination': 0.1},
                    'ensemble': {
                        'behavioral_weight': 0.4,
                        'isolation_weight': 0.3,
                        'static_weight': 0.3
                    }
                },
                'training': {
                    'thresholds': {
                        'min_accuracy': 0.8,
                        'min_precision': 0.75,
                        'min_recall': 0.75,
                        'min_f1_score': 0.75,
                        'min_roc_auc': 0.8
                    }
                }
            }
        }
        
        config_file = temp_dir / "test_config.yaml"
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config, f)
        
        return MLTrainingPipeline(config_path=str(config_file))
    
    @pytest.fixture
    def sample_training_data(self, temp_dir):
        """Create sample training data"""
        data_dir = temp_dir / "training"
        malware_dir = data_dir / "malware"
        benign_dir = data_dir / "benign"
        
        malware_dir.mkdir(parents=True)
        benign_dir.mkdir(parents=True)
        
        # Create sample malware data
        for i in range(5):
            malware_sample = {
                "file_size": 150000 + i * 10000,
                "entropy": 7.5 + i * 0.1,
                "pe_sections": 8 + i,
                "imported_functions": 60 + i * 5,
                "exported_functions": 3 + i,
                "string_entropy": 6.8 + i * 0.1,
                "suspicious_strings": 20 + i * 3,
                "api_calls": 80 + i * 10,
                "network_indicators": 5 + i,
                "file_operations": 10 + i * 2,
                "registry_operations": 8 + i,
                "process_operations": 6 + i,
                "crypto_indicators": 2 + i,
                "packer_indicators": 1,
                "obfuscation_score": 0.8 + i * 0.02
            }
            
            with open(malware_dir / f"malware_{i}.json", 'w') as f:
                json.dump(malware_sample, f)
        
        # Create sample benign data
        for i in range(5):
            benign_sample = {
                "file_size": 50000 + i * 5000,
                "entropy": 6.0 + i * 0.1,
                "pe_sections": 4 + i,
                "imported_functions": 20 + i * 3,
                "exported_functions": 1 + i,
                "string_entropy": 5.0 + i * 0.1,
                "suspicious_strings": 2 + i,
                "api_calls": 15 + i * 3,
                "network_indicators": 0 + i,
                "file_operations": 3 + i,
                "registry_operations": 1 + i,
                "process_operations": 0 + i,
                "crypto_indicators": 0,
                "packer_indicators": 0,
                "obfuscation_score": 0.1 + i * 0.02
            }
            
            with open(benign_dir / f"benign_{i}.json", 'w') as f:
                json.dump(benign_sample, f)
        
        return data_dir
    
    def test_load_training_data(self, training_pipeline, sample_training_data, temp_dir):
        """Test loading training data from JSON files"""
        # Temporarily override DATA_DIR
        original_data_dir = training_pipeline.__class__.__module__
        
        with patch('scripts.train_models.DATA_DIR', sample_training_data):
            X, y = training_pipeline.load_training_data()
        
        # Verify data loading
        assert len(X) == 10  # 5 malware + 5 benign
        assert len(y) == 10
        assert X.shape[1] == 15  # 15 features
        assert sum(y) == 5  # 5 malware samples (label=1)
        assert len(y) - sum(y) == 5  # 5 benign samples (label=0)
    
    def test_synthetic_data_generation(self, training_pipeline):
        """Test synthetic data generation when no real data available"""
        features, labels = training_pipeline._generate_synthetic_data(n_samples=100)
        
        assert len(features) == 100
        assert len(labels) == 100
        assert all(len(feature_vector) == 15 for feature_vector in features)
        assert sum(labels) == 50  # Half malware, half benign
    
    def test_train_models(self, training_pipeline):
        """Test model training functionality"""
        # Generate synthetic data for training
        X, y = training_pipeline._generate_synthetic_data(n_samples=100)
        X = np.array(X)
        y = np.array(y)
        
        # Train models
        models = training_pipeline.train_models(X, y)
        
        # Verify models were created
        assert 'behavioral_analysis' in models
        assert 'isolation_forest' in models
        assert 'ensemble' in models
        assert 'scaler' in models
        
        # Verify model types
        from sklearn.ensemble import RandomForestClassifier, IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        assert isinstance(models['behavioral_analysis']['model'], RandomForestClassifier)
        assert isinstance(models['isolation_forest']['model'], IsolationForest)
        assert isinstance(models['scaler'], StandardScaler)
        
        # Verify metrics exist
        assert 'metrics' in models['behavioral_analysis']
        assert 'metrics' in models['isolation_forest']
        assert 'metrics' in models['ensemble']
        
        # Verify metric values are reasonable
        rf_metrics = models['behavioral_analysis']['metrics']
        assert 0 <= rf_metrics['accuracy'] <= 1
        assert 0 <= rf_metrics['precision'] <= 1
        assert 0 <= rf_metrics['recall'] <= 1
        assert 0 <= rf_metrics['f1_score'] <= 1
        assert 0 <= rf_metrics['roc_auc'] <= 1
    
    def test_save_models(self, training_pipeline, temp_dir):
        """Test model saving functionality"""
        # Generate and train models
        X, y = training_pipeline._generate_synthetic_data(n_samples=50)
        X = np.array(X)
        y = np.array(y)
        
        models = training_pipeline.train_models(X, y)
        
        # Override models directory
        with patch('scripts.train_models.MODELS_DIR', temp_dir):
            saved_files = training_pipeline.save_models(models)
        
        # Verify files were saved
        assert 'behavioral_analysis' in saved_files
        assert 'isolation_forest' in saved_files
        assert 'ensemble_model' in saved_files
        assert 'feature_scaler' in saved_files
        
        # Verify files exist
        for file_path in saved_files.values():
            assert Path(file_path).exists()
            assert Path(file_path).stat().st_size > 0
    
    def test_model_registration(self, training_pipeline, temp_dir):
        """Test model registration with version manager"""
        # Generate and train models
        X, y = training_pipeline._generate_synthetic_data(n_samples=50)
        X = np.array(X)
        y = np.array(y)
        
        models = training_pipeline.train_models(X, y)
        
        # Mock model manager
        with patch('scripts.train_models.ml_model_manager') as mock_manager:
            mock_manager.register_model.return_value = True
            mock_manager.set_active_model.return_value = True
            
            # Override models directory
            with patch('scripts.train_models.MODELS_DIR', temp_dir):
                saved_files = training_pipeline.save_models(models)
                training_pipeline._register_models_with_manager(models, saved_files)
            
            # Verify registration calls
            assert mock_manager.register_model.call_count >= 3  # At least 3 models
            assert mock_manager.set_active_model.call_count >= 3

class TestMLModelManager:
    """Test ML model version management"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def model_manager(self, temp_dir):
        """Create model manager instance for testing"""
        return MLModelManager(models_dir=str(temp_dir), metadata_file=str(temp_dir / "test_metadata.json"))
    
    @pytest.fixture
    def sample_model_file(self, temp_dir):
        """Create a sample model file"""
        model_file = temp_dir / "test_model.pkl"
        
        # Create a simple mock model
        import joblib
        from sklearn.ensemble import RandomForestClassifier
        
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        # Fit with dummy data
        X_dummy = np.random.random((10, 5))
        y_dummy = np.random.randint(0, 2, 10)
        model.fit(X_dummy, y_dummy)
        
        joblib.dump(model, model_file)
        return str(model_file)
    
    def test_register_model(self, model_manager, sample_model_file):
        """Test model registration"""
        success = model_manager.register_model(
            model_type='test_model',
            version='20240101_120000',
            file_path=sample_model_file,
            metrics={'accuracy': 0.95, 'precision': 0.90},
            training_samples=1000,
            feature_count=15,
            algorithm='RandomForest',
            parameters={'n_estimators': 100},
            created_by='test_user',
            notes='Test model registration'
        )
        
        assert success == True
        
        # Verify metadata was stored
        key = 'test_model_20240101_120000'
        assert key in model_manager.metadata
        
        metadata = model_manager.metadata[key]
        assert metadata.model_type == 'test_model'
        assert metadata.version == '20240101_120000'
        assert metadata.metrics['accuracy'] == 0.95
        assert metadata.training_samples == 1000
        assert metadata.algorithm == 'RandomForest'
    
    def test_get_latest_model(self, model_manager, sample_model_file):
        """Test getting latest model version"""
        # Register multiple versions
        versions = ['20240101_120000', '20240102_120000', '20240103_120000']
        
        for version in versions:
            model_manager.register_model(
                model_type='test_model',
                version=version,
                file_path=sample_model_file,
                metrics={'accuracy': 0.95},
                training_samples=1000,
                feature_count=15,
                algorithm='RandomForest'
            )
        
        # Get latest model
        latest = model_manager.get_latest_model('test_model')
        
        assert latest is not None
        assert latest.version == '20240103_120000'  # Latest timestamp
    
    def test_rollback_to_version(self, model_manager, sample_model_file, temp_dir):
        """Test model rollback functionality"""
        # Register a model
        model_manager.register_model(
            model_type='test_model',
            version='20240101_120000',
            file_path=sample_model_file,
            metrics={'accuracy': 0.95},
            training_samples=1000,
            feature_count=15,
            algorithm='RandomForest'
        )
        
        # Test rollback
        success = model_manager.rollback_to('test_model', '20240101_120000')
        
        assert success == True
        
        # Verify symlink was created
        symlink_path = temp_dir / 'test_model.pkl'
        assert symlink_path.is_symlink()
    
    def test_model_stats(self, model_manager, sample_model_file):
        """Test model statistics generation"""
        # Register some models
        model_manager.register_model(
            model_type='behavioral_analysis',
            version='20240101_120000',
            file_path=sample_model_file,
            metrics={'accuracy': 0.95},
            training_samples=1000,
            feature_count=15,
            algorithm='RandomForest'
        )
        
        model_manager.register_model(
            model_type='isolation_forest',
            version='20240101_120000',
            file_path=sample_model_file,
            metrics={'accuracy': 0.85},
            training_samples=1000,
            feature_count=15,
            algorithm='IsolationForest'
        )
        
        stats = model_manager.get_model_stats()
        
        assert 'total_models' in stats
        assert 'model_types' in stats
        assert 'storage_info' in stats
        assert stats['total_models'] == 2
        assert 'behavioral_analysis' in stats['model_types']
        assert 'isolation_forest' in stats['model_types']

class TestMLEvaluationFramework:
    """Test ML evaluation framework"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def evaluation_framework(self, temp_dir):
        """Create evaluation framework instance for testing"""
        # Create temporary config
        config = {
            'machine_learning': {
                'training': {
                    'thresholds': {
                        'min_accuracy': 0.8,
                        'min_precision': 0.75,
                        'min_recall': 0.75,
                        'min_f1_score': 0.75,
                        'min_roc_auc': 0.8
                    }
                },
                'features': {
                    'names': [
                        'file_size', 'entropy', 'pe_sections', 'imported_functions',
                        'exported_functions', 'string_entropy', 'suspicious_strings',
                        'api_calls', 'network_indicators', 'file_operations',
                        'registry_operations', 'process_operations', 'crypto_indicators',
                        'packer_indicators', 'obfuscation_score'
                    ]
                }
            }
        }
        
        config_file = temp_dir / "test_config.yaml"
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config, f)
        
        # Override reports directory
        with patch('src.ml_evaluation.REPORTS_DIR', temp_dir):
            return MLEvaluationFramework(config_path=str(config_file))
    
    @pytest.fixture
    def sample_model_and_data(self):
        """Create sample model and test data"""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        
        # Create sample data
        np.random.seed(42)
        X = np.random.random((100, 15))
        y = np.random.randint(0, 2, 100)
        
        # Create and train model
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        model.fit(X, y)
        
        # Create scaler
        scaler = StandardScaler()
        scaler.fit(X)
        
        return model, scaler, X, y
    
    def test_evaluate_model(self, evaluation_framework, sample_model_and_data):
        """Test individual model evaluation"""
        model, scaler, X, y = sample_model_and_data
        
        # ml_evaluation is imported as the top-level module `ml_evaluation` (src is on
        # sys.path), and it binds ml_model_manager via `from ml_model_manager import ...`,
        # so the live reference is ml_evaluation.ml_model_manager (not src.ml_evaluation).
        with patch('ml_evaluation.ml_model_manager') as mock_manager:
            mock_manager.load_model.side_effect = lambda model_type, version=None: {
                'behavioral_analysis': model,
                'feature_scaler': scaler
            }.get(model_type)
            
            mock_metadata = Mock()
            mock_metadata.version = '20240101_120000'
            mock_manager.get_active_model.return_value = mock_metadata
            
            # Run evaluation
            results = evaluation_framework.evaluate_model('behavioral_analysis', X, y)
        
        # Verify results structure
        assert 'model_type' in results
        assert 'basic_metrics' in results
        assert 'cross_validation' in results
        assert 'threshold_evaluation' in results
        
        # Verify metrics
        metrics = results['basic_metrics']
        assert 'accuracy' in metrics
        assert 'precision' in metrics
        assert 'recall' in metrics
        assert 'f1_score' in metrics
        
        # Verify all metrics are in valid range
        for metric_value in metrics.values():
            assert 0 <= metric_value <= 1
    
    def test_threshold_evaluation(self, evaluation_framework):
        """Test threshold evaluation functionality"""
        metrics = {
            'accuracy': 0.85,
            'precision': 0.80,
            'recall': 0.70,  # Below threshold
            'f1_score': 0.75,
            'roc_auc': 0.85
        }
        
        threshold_results = evaluation_framework._evaluate_against_thresholds(metrics)
        
        assert 'passed' in threshold_results
        assert 'failed_metrics' in threshold_results
        assert 'threshold_checks' in threshold_results
        
        # Should fail because recall is below threshold
        assert threshold_results['passed'] == False
        assert 'recall' in threshold_results['failed_metrics']
    
    def test_markdown_report_generation(self, evaluation_framework, temp_dir):
        """Test markdown report generation"""
        # Mock evaluation results
        evaluation_framework.evaluation_results = {
            'evaluation_timestamp': datetime.now().isoformat(),
            'dataset_info': {
                'total_samples': 100,
                'positive_samples': 50,
                'negative_samples': 50,
                'feature_count': 15
            },
            'summary': {
                'total_models_evaluated': 1,
                'models_passed_thresholds': 1,
                'models_failed_thresholds': 0,
                'best_performing_model': 'behavioral_analysis',
                'overall_status': 'passed'
            },
            'model_evaluations': {
                'behavioral_analysis': {
                    'basic_metrics': {
                        'accuracy': 0.95,
                        'precision': 0.90,
                        'recall': 0.85,
                        'f1_score': 0.87,
                        'roc_auc': 0.92
                    },
                    'threshold_evaluation': {
                        'passed': True,
                        'failed_metrics': [],
                        'threshold_checks': {}
                    }
                }
            }
        }
        
        # Generate report
        with patch('src.ml_evaluation.REPORTS_DIR', temp_dir):
            report_file = evaluation_framework.generate_markdown_report()
        
        # Verify report was created
        assert report_file
        assert Path(report_file).exists()
        
        # Verify report content
        with open(report_file, 'r') as f:
            content = f.read()
        
        assert '# ML Model Evaluation Report' in content
        assert 'behavioral_analysis' in content.lower()
        assert '0.95' in content  # Accuracy value

class TestTrainingPipelineIntegration:
    """Integration tests for the complete training pipeline"""
    
    @pytest.fixture
    def temp_workspace(self):
        """Create temporary workspace for integration testing"""
        temp_dir = tempfile.mkdtemp()
        workspace = Path(temp_dir)
        
        # Create directory structure
        (workspace / "data" / "training" / "malware").mkdir(parents=True)
        (workspace / "data" / "training" / "benign").mkdir(parents=True)
        (workspace / "models").mkdir(parents=True)
        (workspace / "reports").mkdir(parents=True)
        (workspace / "logs").mkdir(parents=True)
        
        yield workspace
        shutil.rmtree(temp_dir)
    
    def test_end_to_end_training_pipeline(self, temp_workspace):
        """Test complete end-to-end training pipeline"""
        # Create sample training data
        self._create_sample_data(temp_workspace)
        
        # Create config file
        config = {
            'machine_learning': {
                'models': {
                    'isolation_forest': {'contamination': 0.1},
                    'ensemble': {
                        'behavioral_weight': 0.4,
                        'isolation_weight': 0.3,
                        'static_weight': 0.3
                    }
                },
                'training': {
                    'thresholds': {
                        'min_accuracy': 0.6,  # Lower thresholds for synthetic data
                        'min_precision': 0.5,
                        'min_recall': 0.5,
                        'min_f1_score': 0.5,
                        'min_roc_auc': 0.6
                    }
                }
            }
        }
        
        config_file = temp_workspace / "config.yaml"
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config, f)
        
        # Run training pipeline
        with patch('scripts.train_models.PROJECT_ROOT', temp_workspace):
            with patch('scripts.train_models.DATA_DIR', temp_workspace / "data" / "training"):
                with patch('scripts.train_models.MODELS_DIR', temp_workspace / "models"):
                    with patch('scripts.train_models.LOGS_DIR', temp_workspace / "logs"):
                        with patch('src.ml_evaluation.REPORTS_DIR', temp_workspace / "reports"):
                            pipeline = MLTrainingPipeline(config_path=str(config_file))
                            
                            # Load data
                            X, y = pipeline.load_training_data()
                            assert len(X) > 0
                            
                            # Train models
                            models = pipeline.train_models(X, y)
                            assert len(models) >= 3
                            
                            # Save models
                            saved_files = pipeline.save_models(models)
                            assert len(saved_files) >= 3
                            
                            # Verify files exist
                            for file_path in saved_files.values():
                                assert Path(file_path).exists()
    
    def _create_sample_data(self, workspace):
        """Create sample training data for integration test"""
        malware_dir = workspace / "data" / "training" / "malware"
        benign_dir = workspace / "data" / "training" / "benign"
        
        # Create malware samples
        for i in range(10):
            sample = {
                "file_size": 150000 + i * 10000,
                "entropy": 7.5,
                "pe_sections": 8,
                "imported_functions": 60,
                "exported_functions": 3,
                "string_entropy": 6.8,
                "suspicious_strings": 20,
                "api_calls": 80,
                "network_indicators": 5,
                "file_operations": 10,
                "registry_operations": 8,
                "process_operations": 6,
                "crypto_indicators": 2,
                "packer_indicators": 1,
                "obfuscation_score": 0.8
            }
            
            with open(malware_dir / f"malware_{i}.json", 'w') as f:
                json.dump(sample, f)
        
        # Create benign samples
        for i in range(10):
            sample = {
                "file_size": 50000,
                "entropy": 6.0,
                "pe_sections": 4,
                "imported_functions": 20,
                "exported_functions": 1,
                "string_entropy": 5.0,
                "suspicious_strings": 2,
                "api_calls": 15,
                "network_indicators": 0,
                "file_operations": 3,
                "registry_operations": 1,
                "process_operations": 0,
                "crypto_indicators": 0,
                "packer_indicators": 0,
                "obfuscation_score": 0.1
            }
            
            with open(benign_dir / f"benign_{i}.json", 'w') as f:
                json.dump(sample, f)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

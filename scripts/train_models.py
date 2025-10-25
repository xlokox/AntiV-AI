#!/usr/bin/env python3
"""
Automated ML Model Training Script for AntiV-AI
Loads labeled datasets, extracts features, trains models, and saves with versioning
"""

import os
import sys
import json
import pickle
import logging
import argparse
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import yaml

# Add src to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import ML model manager and evaluator
from ml_model_manager import ml_model_manager
from ml_evaluation import ml_evaluator

# ML Dependencies
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, classification_report, confusion_matrix
    )
    import joblib
    ML_AVAILABLE = True
except ImportError as e:
    print(f"Error: Required ML libraries not available: {e}")
    print("Please install: pip install scikit-learn pandas numpy")
    sys.exit(1)

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "training"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
CONFIG_FILE = PROJECT_ROOT / "config.yaml"

# Ensure directories exist
MODELS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOGS_DIR / "train_models.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MLTrainingPipeline:
    """Complete ML training pipeline for AntiV-AI"""
    
    def __init__(self, config_path: str = None):
        """Initialize training pipeline"""
        self.config_path = config_path or CONFIG_FILE
        self.config = self._load_config()
        self.ml_config = self.config.get('machine_learning', {})
        
        # Feature names (15 behavioral features)
        self.feature_names = [
            'file_size', 'entropy', 'pe_sections', 'imported_functions',
            'exported_functions', 'string_entropy', 'suspicious_strings',
            'api_calls', 'network_indicators', 'file_operations',
            'registry_operations', 'process_operations', 'crypto_indicators',
            'packer_indicators', 'obfuscation_score'
        ]
        
        # Training metrics
        self.training_metrics = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def load_training_data(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load labeled training data from data/training/ directory
        
        Expected structure:
        data/training/
        ├── malware/
        │   ├── sample1.json
        │   └── sample2.json
        └── benign/
            ├── sample1.json
            └── sample2.json
        
        Each JSON file contains extracted features and metadata
        """
        logger.info("Loading training data...")
        
        features = []
        labels = []
        
        # Load malware samples (label = 1)
        malware_dir = DATA_DIR / "malware"
        if malware_dir.exists():
            malware_count = self._load_samples_from_dir(malware_dir, features, labels, label=1)
            logger.info(f"Loaded {malware_count} malware samples")
        else:
            logger.warning(f"Malware directory not found: {malware_dir}")
        
        # Load benign samples (label = 0)
        benign_dir = DATA_DIR / "benign"
        if benign_dir.exists():
            benign_count = self._load_samples_from_dir(benign_dir, features, labels, label=0)
            logger.info(f"Loaded {benign_count} benign samples")
        else:
            logger.warning(f"Benign directory not found: {benign_dir}")
        
        if not features:
            # Generate synthetic data for demonstration
            logger.warning("No training data found, generating synthetic data for testing")
            features, labels = self._generate_synthetic_data()
        
        features_array = np.array(features)
        labels_array = np.array(labels)
        
        logger.info(f"Total samples loaded: {len(features_array)} (malware: {sum(labels_array)}, benign: {len(labels_array) - sum(labels_array)})")
        
        return features_array, labels_array
    
    def _load_samples_from_dir(self, directory: Path, features: List, labels: List, label: int) -> int:
        """Load samples from a directory"""
        count = 0
        
        for json_file in directory.glob("*.json"):
            try:
                with open(json_file, 'r') as f:
                    sample_data = json.load(f)
                
                # Extract features in the correct order
                sample_features = []
                for feature_name in self.feature_names:
                    value = sample_data.get(feature_name, 0.0)
                    # Ensure numeric value
                    if isinstance(value, (int, float)):
                        sample_features.append(float(value))
                    else:
                        sample_features.append(0.0)
                
                features.append(sample_features)
                labels.append(label)
                count += 1
                
            except Exception as e:
                logger.error(f"Error loading sample {json_file}: {e}")
        
        return count
    
    def _generate_synthetic_data(self, n_samples: int = 1000) -> Tuple[List, List]:
        """Generate synthetic training data for testing"""
        logger.info(f"Generating {n_samples} synthetic samples...")
        
        np.random.seed(42)  # For reproducibility
        features = []
        labels = []
        
        for i in range(n_samples):
            if i < n_samples // 2:
                # Benign samples
                label = 0
                sample = [
                    np.random.normal(50000, 20000),    # file_size
                    np.random.normal(6.5, 1.0),        # entropy
                    np.random.randint(3, 8),           # pe_sections
                    np.random.randint(10, 50),         # imported_functions
                    np.random.randint(0, 5),           # exported_functions
                    np.random.normal(5.0, 1.0),        # string_entropy
                    np.random.randint(0, 10),          # suspicious_strings
                    np.random.randint(5, 30),          # api_calls
                    np.random.randint(0, 3),           # network_indicators
                    np.random.randint(0, 5),           # file_operations
                    np.random.randint(0, 3),           # registry_operations
                    np.random.randint(0, 2),           # process_operations
                    np.random.randint(0, 2),           # crypto_indicators
                    0,                                 # packer_indicators
                    np.random.normal(0.2, 0.1)         # obfuscation_score
                ]
            else:
                # Malware samples
                label = 1
                sample = [
                    np.random.normal(100000, 50000),   # file_size (larger)
                    np.random.normal(7.5, 0.5),        # entropy (higher)
                    np.random.randint(5, 15),          # pe_sections (more)
                    np.random.randint(30, 100),        # imported_functions (more)
                    np.random.randint(0, 10),          # exported_functions
                    np.random.normal(6.5, 1.0),        # string_entropy (higher)
                    np.random.randint(5, 50),          # suspicious_strings (more)
                    np.random.randint(20, 100),        # api_calls (more)
                    np.random.randint(1, 10),          # network_indicators (more)
                    np.random.randint(2, 20),          # file_operations (more)
                    np.random.randint(1, 15),          # registry_operations (more)
                    np.random.randint(1, 10),          # process_operations (more)
                    np.random.randint(0, 5),           # crypto_indicators
                    np.random.choice([0, 1]),          # packer_indicators
                    np.random.normal(0.7, 0.2)         # obfuscation_score (higher)
                ]
            
            # Ensure all values are positive and reasonable
            sample = [max(0, val) for val in sample]
            features.append(sample)
            labels.append(label)
        
        return features, labels
    
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train all ML models"""
        logger.info("Starting model training...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Feature scaling
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        models = {}
        
        # Train RandomForest (Behavioral Analysis)
        logger.info("Training RandomForest model...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train_scaled, y_train)
        
        # Evaluate RandomForest
        rf_pred = rf_model.predict(X_test_scaled)
        rf_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
        
        rf_metrics = {
            'accuracy': accuracy_score(y_test, rf_pred),
            'precision': precision_score(y_test, rf_pred),
            'recall': recall_score(y_test, rf_pred),
            'f1_score': f1_score(y_test, rf_pred),
            'roc_auc': roc_auc_score(y_test, rf_pred_proba)
        }
        
        models['behavioral_analysis'] = {
            'model': rf_model,
            'metrics': rf_metrics,
            'feature_importance': dict(zip(self.feature_names, rf_model.feature_importances_))
        }
        
        # Train IsolationForest (Anomaly Detection)
        logger.info("Training IsolationForest model...")
        contamination = self.ml_config.get('models', {}).get('isolation_forest', {}).get('contamination', 0.1)
        
        iso_model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        iso_model.fit(X_train_scaled)
        
        # Evaluate IsolationForest (anomaly detection)
        iso_pred = iso_model.predict(X_test_scaled)
        iso_pred_binary = (iso_pred == -1).astype(int)  # -1 = anomaly, 1 = normal
        
        iso_metrics = {
            'accuracy': accuracy_score(y_test, iso_pred_binary),
            'precision': precision_score(y_test, iso_pred_binary, zero_division=0),
            'recall': recall_score(y_test, iso_pred_binary, zero_division=0),
            'f1_score': f1_score(y_test, iso_pred_binary, zero_division=0)
        }
        
        models['isolation_forest'] = {
            'model': iso_model,
            'metrics': iso_metrics
        }
        
        # Create Ensemble Model
        logger.info("Creating ensemble model...")
        ensemble_weights = self.ml_config.get('models', {}).get('ensemble', {})
        behavioral_weight = ensemble_weights.get('behavioral_weight', 0.4)
        isolation_weight = ensemble_weights.get('isolation_weight', 0.3)
        static_weight = ensemble_weights.get('static_weight', 0.3)
        
        # Ensemble prediction (simplified for this implementation)
        rf_scores = rf_model.predict_proba(X_test_scaled)[:, 1]
        iso_scores = (iso_model.decision_function(X_test_scaled) + 0.5) / 1.0  # Normalize to 0-1
        
        # Combine scores (static analysis would be added here in real implementation)
        ensemble_scores = (
            behavioral_weight * rf_scores +
            isolation_weight * (1 - iso_scores)  # Invert isolation scores
        ) / (behavioral_weight + isolation_weight)
        
        ensemble_pred = (ensemble_scores > 0.5).astype(int)
        
        ensemble_metrics = {
            'accuracy': accuracy_score(y_test, ensemble_pred),
            'precision': precision_score(y_test, ensemble_pred),
            'recall': recall_score(y_test, ensemble_pred),
            'f1_score': f1_score(y_test, ensemble_pred),
            'roc_auc': roc_auc_score(y_test, ensemble_scores)
        }
        
        models['ensemble'] = {
            'model': {
                'behavioral_model': rf_model,
                'isolation_model': iso_model,
                'scaler': scaler,
                'weights': {
                    'behavioral_weight': behavioral_weight,
                    'isolation_weight': isolation_weight,
                    'static_weight': static_weight
                }
            },
            'metrics': ensemble_metrics
        }
        
        # Store scaler separately
        models['scaler'] = scaler
        
        # Log training metrics
        self.training_metrics = {
            'timestamp': self.timestamp,
            'training_samples': len(X_train),
            'test_samples': len(X_test),
            'feature_count': X.shape[1],
            'models': {
                'behavioral_analysis': rf_metrics,
                'isolation_forest': iso_metrics,
                'ensemble': ensemble_metrics
            }
        }
        
        logger.info("Model training completed successfully")
        return models
    
    def save_models(self, models: Dict[str, Any]) -> Dict[str, str]:
        """Save trained models with timestamped filenames"""
        logger.info("Saving trained models...")
        
        saved_files = {}
        
        # Save individual models
        model_files = {
            'behavioral_analysis': f"behavioral_analysis_{self.timestamp}.pkl",
            'isolation_forest': f"isolation_forest_{self.timestamp}.pkl",
            'ensemble_model': f"ensemble_model_{self.timestamp}.pkl",
            'feature_scaler': f"feature_scaler_{self.timestamp}.pkl"
        }
        
        try:
            # Save RandomForest model
            rf_path = MODELS_DIR / model_files['behavioral_analysis']
            joblib.dump(models['behavioral_analysis']['model'], rf_path)
            saved_files['behavioral_analysis'] = str(rf_path)
            
            # Save IsolationForest model
            iso_path = MODELS_DIR / model_files['isolation_forest']
            joblib.dump(models['isolation_forest']['model'], iso_path)
            saved_files['isolation_forest'] = str(iso_path)
            
            # Save Ensemble model
            ensemble_path = MODELS_DIR / model_files['ensemble_model']
            joblib.dump(models['ensemble']['model'], ensemble_path)
            saved_files['ensemble_model'] = str(ensemble_path)
            
            # Save Scaler
            scaler_path = MODELS_DIR / model_files['feature_scaler']
            joblib.dump(models['scaler'], scaler_path)
            saved_files['feature_scaler'] = str(scaler_path)
            
            # Create symlinks to latest models
            self._create_latest_symlinks(model_files)

            # Register models with version manager
            self._register_models_with_manager(models, saved_files)

            logger.info(f"Models saved successfully: {list(saved_files.keys())}")

        except Exception as e:
            logger.error(f"Error saving models: {e}")
            raise

        return saved_files
    
    def _create_latest_symlinks(self, model_files: Dict[str, str]):
        """Create symlinks to the latest model versions"""
        try:
            latest_files = {
                'behavioral_analysis.pkl': model_files['behavioral_analysis'],
                'isolation_forest.pkl': model_files['isolation_forest'],
                'ensemble_model.pkl': model_files['ensemble_model'],
                'feature_scaler.pkl': model_files['feature_scaler']
            }
            
            for latest_name, timestamped_name in latest_files.items():
                latest_path = MODELS_DIR / latest_name
                timestamped_path = MODELS_DIR / timestamped_name
                
                # Remove existing symlink
                if latest_path.is_symlink():
                    latest_path.unlink()
                elif latest_path.exists():
                    latest_path.rename(latest_path.with_suffix('.pkl.backup'))
                
                # Create new symlink
                latest_path.symlink_to(timestamped_name)
                
        except Exception as e:
            logger.warning(f"Could not create symlinks: {e}")

    def _register_models_with_manager(self, models: Dict[str, Any], saved_files: Dict[str, str]):
        """Register trained models with the version manager"""
        try:
            # Register behavioral analysis model
            if 'behavioral_analysis' in models and 'behavioral_analysis' in saved_files:
                ml_model_manager.register_model(
                    model_type='behavioral_analysis',
                    version=self.timestamp,
                    file_path=saved_files['behavioral_analysis'],
                    metrics=models['behavioral_analysis']['metrics'],
                    training_samples=self.training_metrics.get('training_samples', 0),
                    feature_count=self.training_metrics.get('feature_count', 0),
                    algorithm='RandomForest',
                    parameters={
                        'n_estimators': 100,
                        'max_depth': 10,
                        'random_state': 42
                    },
                    created_by='training_script',
                    notes=f'Automated training session {self.timestamp}'
                )

                # Set as active model
                ml_model_manager.set_active_model('behavioral_analysis', self.timestamp)

            # Register isolation forest model
            if 'isolation_forest' in models and 'isolation_forest' in saved_files:
                contamination = self.ml_config.get('models', {}).get('isolation_forest', {}).get('contamination', 0.1)

                ml_model_manager.register_model(
                    model_type='isolation_forest',
                    version=self.timestamp,
                    file_path=saved_files['isolation_forest'],
                    metrics=models['isolation_forest']['metrics'],
                    training_samples=self.training_metrics.get('training_samples', 0),
                    feature_count=self.training_metrics.get('feature_count', 0),
                    algorithm='IsolationForest',
                    parameters={
                        'contamination': contamination,
                        'random_state': 42
                    },
                    created_by='training_script',
                    notes=f'Automated training session {self.timestamp}'
                )

                # Set as active model
                ml_model_manager.set_active_model('isolation_forest', self.timestamp)

            # Register ensemble model
            if 'ensemble' in models and 'ensemble_model' in saved_files:
                ml_model_manager.register_model(
                    model_type='ensemble',
                    version=self.timestamp,
                    file_path=saved_files['ensemble_model'],
                    metrics=models['ensemble']['metrics'],
                    training_samples=self.training_metrics.get('training_samples', 0),
                    feature_count=self.training_metrics.get('feature_count', 0),
                    algorithm='Ensemble',
                    parameters=models['ensemble']['model']['weights'],
                    created_by='training_script',
                    notes=f'Automated training session {self.timestamp}'
                )

                # Set as active model
                ml_model_manager.set_active_model('ensemble', self.timestamp)

            logger.info("Models registered with version manager successfully")

        except Exception as e:
            logger.error(f"Error registering models with version manager: {e}")

    def log_training_metrics(self):
        """Log training metrics to file"""
        metrics_log_file = LOGS_DIR / "train_metrics.log"
        
        try:
            # Append metrics to log file
            with open(metrics_log_file, 'a') as f:
                f.write(f"\n{'='*50}\n")
                f.write(f"Training Session: {self.timestamp}\n")
                f.write(f"{'='*50}\n")
                
                for model_name, metrics in self.training_metrics['models'].items():
                    f.write(f"\n{model_name.upper()} METRICS:\n")
                    f.write(f"  Accuracy:  {metrics['accuracy']:.4f}\n")
                    f.write(f"  Precision: {metrics['precision']:.4f}\n")
                    f.write(f"  Recall:    {metrics['recall']:.4f}\n")
                    f.write(f"  F1-Score:  {metrics['f1_score']:.4f}\n")
                    if 'roc_auc' in metrics:
                        f.write(f"  ROC AUC:   {metrics['roc_auc']:.4f}\n")
                
                f.write(f"\nTraining Samples: {self.training_metrics['training_samples']}\n")
                f.write(f"Test Samples: {self.training_metrics['test_samples']}\n")
                f.write(f"Features: {self.training_metrics['feature_count']}\n")
                f.write(f"Timestamp: {self.training_metrics['timestamp']}\n")
            
            logger.info(f"Training metrics logged to {metrics_log_file}")
            
        except Exception as e:
            logger.error(f"Error logging metrics: {e}")

def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description="Train AntiV-AI ML models")
    parser.add_argument("--config", help="Path to config file", default=None)
    parser.add_argument("--data-dir", help="Path to training data directory", default=None)
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize training pipeline
        pipeline = MLTrainingPipeline(config_path=args.config)
        
        # Override data directory if specified
        if args.data_dir:
            global DATA_DIR
            DATA_DIR = Path(args.data_dir)
        
        logger.info("Starting ML model training pipeline...")
        
        # Load training data
        X, y = pipeline.load_training_data()
        
        if len(X) == 0:
            logger.error("No training data available")
            return 1
        
        # Train models
        models = pipeline.train_models(X, y)
        
        # Save models
        saved_files = pipeline.save_models(models)
        
        # Log metrics
        pipeline.log_training_metrics()

        # Run evaluation and generate report
        logger.info("Running model evaluation...")
        evaluation_results = ml_evaluator.evaluate_all_models(X, y)

        # Generate markdown report
        report_file = ml_evaluator.generate_markdown_report()
        if report_file:
            logger.info(f"Evaluation report generated: {report_file}")

        logger.info("Training pipeline completed successfully!")
        logger.info(f"Saved models: {list(saved_files.keys())}")

        # Print summary
        print("\n" + "="*50)
        print("TRAINING SUMMARY")
        print("="*50)
        for model_name, metrics in pipeline.training_metrics['models'].items():
            print(f"\n{model_name.upper()}:")
            print(f"  Accuracy:  {metrics['accuracy']:.4f}")
            print(f"  Precision: {metrics['precision']:.4f}")
            print(f"  Recall:    {metrics['recall']:.4f}")
            print(f"  F1-Score:  {metrics['f1_score']:.4f}")
            if 'roc_auc' in metrics:
                print(f"  ROC AUC:   {metrics['roc_auc']:.4f}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Training pipeline failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

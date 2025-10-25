"""
Advanced ML Threat Detection for AntiV-AI
Implements behavioral analysis with IsolationForest and ensemble models
"""

import os
import pickle
import numpy as np
import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import json
import sqlite3
from pathlib import Path

# ML Dependencies
try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Model configuration
MODEL_DIR = "models"
BEHAVIORAL_MODEL_PATH = os.path.join(MODEL_DIR, "behavioral_analysis.pkl")
ISOLATION_FOREST_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "feature_scaler.pkl")
ENSEMBLE_MODEL_PATH = os.path.join(MODEL_DIR, "ensemble_model.pkl")

@dataclass
class MLPrediction:
    """ML prediction result"""
    confidence_score: float  # 0.0 = benign, 1.0 = malicious
    threat_probability: float
    anomaly_score: float
    feature_importance: Dict[str, float]
    model_version: str
    prediction_timestamp: str

@dataclass
class BehavioralFeatures:
    """Behavioral features for ML analysis"""
    file_size: float
    entropy: float
    pe_sections: int
    imported_functions: int
    exported_functions: int
    string_entropy: float
    suspicious_strings: int
    api_calls: int
    network_indicators: int
    file_operations: int
    registry_operations: int
    process_operations: int
    crypto_indicators: int
    packer_indicators: int
    obfuscation_score: float

class MLThreatDetector:
    """Advanced ML-based threat detection system"""
    
    def __init__(self):
        """Initialize ML threat detector"""
        self.logger = logging.getLogger(__name__)
        
        if not ML_AVAILABLE:
            self.logger.warning("ML dependencies not available - using fallback detection")
            self.ml_enabled = False
            return
        
        self.ml_enabled = True
        self.models = {}
        self.scaler = None
        self.feature_names = []
        
        # Initialize model directory
        os.makedirs(MODEL_DIR, exist_ok=True)
        
        # Load or create models
        self._load_models()
        
        # Initialize prediction database
        self._init_prediction_db()
    
    def _init_prediction_db(self):
        """Initialize ML prediction database"""
        try:
            db_path = "data/ml_predictions.db"
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ml_predictions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        file_hash TEXT,
                        confidence_score REAL NOT NULL,
                        threat_probability REAL NOT NULL,
                        anomaly_score REAL NOT NULL,
                        model_version TEXT NOT NULL,
                        features TEXT NOT NULL,
                        prediction_timestamp TEXT NOT NULL
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_ml_hash 
                    ON ml_predictions(file_hash)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_ml_timestamp 
                    ON ml_predictions(prediction_timestamp)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing ML prediction database: {str(e)}")
    
    def _load_models(self):
        """Load ML models from disk or create new ones"""
        try:
            # Load behavioral analysis model
            if os.path.exists(BEHAVIORAL_MODEL_PATH):
                self.models['behavioral'] = joblib.load(BEHAVIORAL_MODEL_PATH)
                self.logger.info("Loaded behavioral analysis model")
            else:
                self.models['behavioral'] = self._create_behavioral_model()
                self.logger.info("Created new behavioral analysis model")
            
            # Load isolation forest
            if os.path.exists(ISOLATION_FOREST_PATH):
                self.models['isolation_forest'] = joblib.load(ISOLATION_FOREST_PATH)
                self.logger.info("Loaded isolation forest model")
            else:
                self.models['isolation_forest'] = self._create_isolation_forest()
                self.logger.info("Created new isolation forest model")
            
            # Load feature scaler
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
                self.logger.info("Loaded feature scaler")
            else:
                self.scaler = StandardScaler()
                self.logger.info("Created new feature scaler")
            
            # Load ensemble model
            if os.path.exists(ENSEMBLE_MODEL_PATH):
                self.models['ensemble'] = joblib.load(ENSEMBLE_MODEL_PATH)
                self.logger.info("Loaded ensemble model")
            else:
                self.models['ensemble'] = self._create_ensemble_model()
                self.logger.info("Created new ensemble model")
            
        except Exception as e:
            self.logger.error(f"Error loading ML models: {str(e)}")
            self.ml_enabled = False
    
    def _create_behavioral_model(self) -> RandomForestClassifier:
        """Create behavioral analysis model"""
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        
        # Generate synthetic training data for demonstration
        X_train, y_train = self._generate_synthetic_data(1000)
        
        if self.scaler is None:
            self.scaler = StandardScaler()
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        model.fit(X_train_scaled, y_train)
        
        # Save model
        joblib.dump(model, BEHAVIORAL_MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        
        return model
    
    def _create_isolation_forest(self) -> IsolationForest:
        """Create isolation forest for anomaly detection"""
        model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        # Generate synthetic data for training
        X_train, _ = self._generate_synthetic_data(500)
        X_train_scaled = self.scaler.transform(X_train) if self.scaler else X_train
        
        model.fit(X_train_scaled)
        
        # Save model
        joblib.dump(model, ISOLATION_FOREST_PATH)
        
        return model
    
    def _create_ensemble_model(self) -> Dict:
        """Create ensemble model combining multiple approaches"""
        ensemble = {
            'behavioral_weight': 0.4,
            'isolation_weight': 0.3,
            'static_weight': 0.3,
            'version': '1.0'
        }
        
        # Save ensemble configuration
        joblib.dump(ensemble, ENSEMBLE_MODEL_PATH)
        
        return ensemble
    
    def _generate_synthetic_data(self, n_samples: int) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for demonstration"""
        np.random.seed(42)
        
        # Generate features
        features = []
        labels = []
        
        for i in range(n_samples):
            # Benign files (70%)
            if i < n_samples * 0.7:
                feature_vector = [
                    np.random.normal(50000, 20000),  # file_size
                    np.random.normal(6.5, 1.0),     # entropy
                    np.random.randint(3, 8),        # pe_sections
                    np.random.randint(50, 200),     # imported_functions
                    np.random.randint(0, 10),       # exported_functions
                    np.random.normal(5.0, 1.0),     # string_entropy
                    np.random.randint(0, 5),        # suspicious_strings
                    np.random.randint(20, 100),     # api_calls
                    np.random.randint(0, 3),        # network_indicators
                    np.random.randint(5, 20),       # file_operations
                    np.random.randint(0, 5),        # registry_operations
                    np.random.randint(1, 10),       # process_operations
                    np.random.randint(0, 2),        # crypto_indicators
                    np.random.randint(0, 1),        # packer_indicators
                    np.random.normal(0.2, 0.1)      # obfuscation_score
                ]
                labels.append(0)  # Benign
            else:
                # Malicious files (30%)
                feature_vector = [
                    np.random.normal(100000, 50000), # file_size
                    np.random.normal(7.8, 0.5),      # entropy
                    np.random.randint(6, 15),        # pe_sections
                    np.random.randint(100, 500),     # imported_functions
                    np.random.randint(5, 50),        # exported_functions
                    np.random.normal(7.0, 0.5),      # string_entropy
                    np.random.randint(10, 50),       # suspicious_strings
                    np.random.randint(100, 500),     # api_calls
                    np.random.randint(5, 20),        # network_indicators
                    np.random.randint(20, 100),      # file_operations
                    np.random.randint(10, 50),       # registry_operations
                    np.random.randint(10, 50),       # process_operations
                    np.random.randint(3, 10),        # crypto_indicators
                    np.random.randint(1, 5),         # packer_indicators
                    np.random.normal(0.8, 0.1)       # obfuscation_score
                ]
                labels.append(1)  # Malicious
            
            features.append(feature_vector)
        
        self.feature_names = [
            'file_size', 'entropy', 'pe_sections', 'imported_functions',
            'exported_functions', 'string_entropy', 'suspicious_strings',
            'api_calls', 'network_indicators', 'file_operations',
            'registry_operations', 'process_operations', 'crypto_indicators',
            'packer_indicators', 'obfuscation_score'
        ]
        
        return np.array(features), np.array(labels)
    
    def _extract_behavioral_features(self, file_path: str, analysis_result: Dict) -> BehavioralFeatures:
        """Extract behavioral features from file analysis"""
        try:
            # Extract features from analysis result
            pe_analysis = analysis_result.get('pe_analysis', {})
            
            features = BehavioralFeatures(
                file_size=float(analysis_result.get('file_size', 0)),
                entropy=float(analysis_result.get('entropy', 0.0)),
                pe_sections=len(pe_analysis.get('sections', [])),
                imported_functions=len(pe_analysis.get('imports', [])),
                exported_functions=len(pe_analysis.get('exports', [])),
                string_entropy=float(analysis_result.get('string_entropy', 0.0)),
                suspicious_strings=len(analysis_result.get('suspicious_strings', [])),
                api_calls=len(analysis_result.get('api_calls', [])),
                network_indicators=len(analysis_result.get('network_indicators', [])),
                file_operations=len(analysis_result.get('file_operations', [])),
                registry_operations=len(analysis_result.get('registry_operations', [])),
                process_operations=len(analysis_result.get('process_operations', [])),
                crypto_indicators=len(analysis_result.get('crypto_indicators', [])),
                packer_indicators=int(analysis_result.get('packed', False)),
                obfuscation_score=float(analysis_result.get('obfuscation_score', 0.0))
            )
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting behavioral features: {str(e)}")
            # Return default features
            return BehavioralFeatures(
                file_size=0.0, entropy=0.0, pe_sections=0, imported_functions=0,
                exported_functions=0, string_entropy=0.0, suspicious_strings=0,
                api_calls=0, network_indicators=0, file_operations=0,
                registry_operations=0, process_operations=0, crypto_indicators=0,
                packer_indicators=0, obfuscation_score=0.0
            )
    
    async def analyze_behavior(self, file_path: str, analysis_result: Dict = None) -> MLPrediction:
        """
        Analyze file behavior using ML models
        
        Args:
            file_path: Path to the file to analyze
            analysis_result: Optional pre-computed analysis result
            
        Returns:
            MLPrediction with confidence score and details
        """
        if not self.ml_enabled:
            # Fallback prediction
            return MLPrediction(
                confidence_score=0.5,
                threat_probability=0.5,
                anomaly_score=0.0,
                feature_importance={},
                model_version="fallback",
                prediction_timestamp=datetime.now().isoformat()
            )
        
        try:
            # If no analysis result provided, perform basic analysis
            if analysis_result is None:
                from file_analysis import FileAnalyzer
                analyzer = FileAnalyzer()
                analysis_result = analyzer.analyze_file(file_path)
            
            # Extract behavioral features
            features = self._extract_behavioral_features(file_path, analysis_result)
            
            # Convert to feature vector
            feature_vector = np.array([
                features.file_size, features.entropy, features.pe_sections,
                features.imported_functions, features.exported_functions,
                features.string_entropy, features.suspicious_strings,
                features.api_calls, features.network_indicators,
                features.file_operations, features.registry_operations,
                features.process_operations, features.crypto_indicators,
                features.packer_indicators, features.obfuscation_score
            ]).reshape(1, -1)
            
            # Scale features
            if self.scaler:
                feature_vector_scaled = self.scaler.transform(feature_vector)
            else:
                feature_vector_scaled = feature_vector
            
            # Get predictions from different models
            predictions = {}
            
            # Behavioral model prediction
            if 'behavioral' in self.models:
                behavioral_pred = self.models['behavioral'].predict_proba(feature_vector_scaled)[0]
                predictions['behavioral'] = behavioral_pred[1] if len(behavioral_pred) > 1 else 0.5
            
            # Isolation forest anomaly detection
            if 'isolation_forest' in self.models:
                anomaly_score = self.models['isolation_forest'].decision_function(feature_vector_scaled)[0]
                # Convert to probability (higher anomaly = higher threat)
                anomaly_prob = max(0.0, min(1.0, (1 - anomaly_score) / 2))
                predictions['isolation'] = anomaly_prob
            
            # Ensemble prediction
            ensemble_config = self.models.get('ensemble', {})
            behavioral_weight = ensemble_config.get('behavioral_weight', 0.5)
            isolation_weight = ensemble_config.get('isolation_weight', 0.5)
            
            confidence_score = (
                predictions.get('behavioral', 0.5) * behavioral_weight +
                predictions.get('isolation', 0.5) * isolation_weight
            )
            
            # Calculate feature importance
            feature_importance = {}
            if 'behavioral' in self.models and hasattr(self.models['behavioral'], 'feature_importances_'):
                importances = self.models['behavioral'].feature_importances_
                for i, importance in enumerate(importances):
                    if i < len(self.feature_names):
                        feature_importance[self.feature_names[i]] = float(importance)
            
            # Create prediction result
            prediction = MLPrediction(
                confidence_score=float(confidence_score),
                threat_probability=float(predictions.get('behavioral', 0.5)),
                anomaly_score=float(predictions.get('isolation', 0.0)),
                feature_importance=feature_importance,
                model_version=ensemble_config.get('version', '1.0'),
                prediction_timestamp=datetime.now().isoformat()
            )
            
            # Store prediction in database
            self._store_prediction(file_path, analysis_result.get('sha256', ''), prediction, features)
            
            return prediction
            
        except Exception as e:
            self.logger.error(f"ML behavior analysis failed: {str(e)}")
            # Return fallback prediction
            return MLPrediction(
                confidence_score=0.5,
                threat_probability=0.5,
                anomaly_score=0.0,
                feature_importance={},
                model_version="error",
                prediction_timestamp=datetime.now().isoformat()
            )
    
    def _store_prediction(self, file_path: str, file_hash: str, prediction: MLPrediction, features: BehavioralFeatures):
        """Store ML prediction in database"""
        try:
            db_path = "data/ml_predictions.db"
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO ml_predictions 
                    (file_path, file_hash, confidence_score, threat_probability, 
                     anomaly_score, model_version, features, prediction_timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_path,
                    file_hash,
                    prediction.confidence_score,
                    prediction.threat_probability,
                    prediction.anomaly_score,
                    prediction.model_version,
                    json.dumps(features.__dict__),
                    prediction.prediction_timestamp
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing ML prediction: {str(e)}")
    
    def retrain_models(self, training_data: List[Tuple[str, int]]) -> bool:
        """
        Retrain ML models with new data
        
        Args:
            training_data: List of (file_path, label) tuples
            
        Returns:
            True if retraining successful
        """
        if not self.ml_enabled:
            return False
        
        try:
            self.logger.info(f"Retraining ML models with {len(training_data)} samples")
            
            # Extract features from training data
            features = []
            labels = []
            
            for file_path, label in training_data:
                try:
                    from file_analysis import FileAnalyzer
                    analyzer = FileAnalyzer()
                    analysis_result = analyzer.analyze_file(file_path)
                    
                    behavioral_features = self._extract_behavioral_features(file_path, analysis_result)
                    
                    feature_vector = [
                        behavioral_features.file_size, behavioral_features.entropy,
                        behavioral_features.pe_sections, behavioral_features.imported_functions,
                        behavioral_features.exported_functions, behavioral_features.string_entropy,
                        behavioral_features.suspicious_strings, behavioral_features.api_calls,
                        behavioral_features.network_indicators, behavioral_features.file_operations,
                        behavioral_features.registry_operations, behavioral_features.process_operations,
                        behavioral_features.crypto_indicators, behavioral_features.packer_indicators,
                        behavioral_features.obfuscation_score
                    ]
                    
                    features.append(feature_vector)
                    labels.append(label)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing training file {file_path}: {str(e)}")
                    continue
            
            if len(features) < 10:
                self.logger.error("Insufficient training data for retraining")
                return False
            
            X = np.array(features)
            y = np.array(labels)
            
            # Retrain scaler
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            
            # Retrain behavioral model
            self.models['behavioral'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                class_weight='balanced'
            )
            self.models['behavioral'].fit(X_scaled, y)
            
            # Retrain isolation forest
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
            self.models['isolation_forest'].fit(X_scaled)
            
            # Save retrained models
            joblib.dump(self.models['behavioral'], BEHAVIORAL_MODEL_PATH)
            joblib.dump(self.models['isolation_forest'], ISOLATION_FOREST_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
            
            self.logger.info("ML models retrained successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Model retraining failed: {str(e)}")
            return False
    
    def get_model_statistics(self) -> Dict:
        """Get ML model statistics"""
        try:
            db_path = "data/ml_predictions.db"
            
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                
                # Total predictions
                cursor.execute("SELECT COUNT(*) FROM ml_predictions")
                total_predictions = cursor.fetchone()[0]
                
                # Recent predictions (last 24 hours)
                cursor.execute('''
                    SELECT COUNT(*) FROM ml_predictions 
                    WHERE prediction_timestamp > datetime('now', '-24 hours')
                ''')
                recent_predictions = cursor.fetchone()[0]
                
                # Threat distribution
                cursor.execute('''
                    SELECT 
                        AVG(confidence_score),
                        AVG(threat_probability),
                        AVG(anomaly_score)
                    FROM ml_predictions
                ''')
                avg_scores = cursor.fetchone()
                
                return {
                    'ml_enabled': self.ml_enabled,
                    'total_predictions': total_predictions,
                    'recent_predictions_24h': recent_predictions,
                    'average_confidence': avg_scores[0] if avg_scores[0] else 0.0,
                    'average_threat_probability': avg_scores[1] if avg_scores[1] else 0.0,
                    'average_anomaly_score': avg_scores[2] if avg_scores[2] else 0.0,
                    'models_loaded': list(self.models.keys()),
                    'feature_count': len(self.feature_names)
                }
                
        except Exception as e:
            self.logger.error(f"Error getting ML statistics: {str(e)}")
            return {
                'ml_enabled': self.ml_enabled,
                'error': str(e)
            }

# Global ML detector instance
ml_detector = MLThreatDetector()

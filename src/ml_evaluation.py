"""
ML Model Evaluation and Validation Framework for AntiV-AI
Provides comprehensive model evaluation with cross-validation and reporting
"""

import os
import sys
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
import yaml

# ML Dependencies
try:
    from sklearn.model_selection import cross_val_score, StratifiedKFold
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        roc_auc_score, confusion_matrix, classification_report,
        precision_recall_curve, roc_curve
    )
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Add src to path for imports
sys.path.append(os.path.dirname(__file__))
from ml_model_manager import ml_model_manager

# Configuration
PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
CONFIG_FILE = PROJECT_ROOT / "config.yaml"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MLEvaluationFramework:
    """ML Model Evaluation and Validation Framework"""
    
    def __init__(self, config_path: str = None):
        """Initialize evaluation framework"""
        self.config_path = config_path or CONFIG_FILE
        self.config = self._load_config()
        self.ml_config = self.config.get('machine_learning', {})
        self.thresholds = self.ml_config.get('training', {}).get('thresholds', {})
        
        # Feature names
        self.feature_names = self.ml_config.get('features', {}).get('names', [
            'file_size', 'entropy', 'pe_sections', 'imported_functions',
            'exported_functions', 'string_entropy', 'suspicious_strings',
            'api_calls', 'network_indicators', 'file_operations',
            'registry_operations', 'process_operations', 'crypto_indicators',
            'packer_indicators', 'obfuscation_score'
        ])
        
        self.evaluation_results = {}
        
    def _load_config(self) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def evaluate_model(
        self,
        model_type: str,
        X: np.ndarray,
        y: np.ndarray,
        model_version: str = None,
        cv_folds: int = 5
    ) -> Dict[str, Any]:
        """
        Comprehensive model evaluation with cross-validation
        
        Args:
            model_type: Type of model to evaluate
            X: Feature matrix
            y: Target labels
            model_version: Specific model version (if None, uses active)
            cv_folds: Number of cross-validation folds
            
        Returns:
            Dictionary containing evaluation results
        """
        logger.info(f"Starting evaluation for {model_type} model...")
        
        try:
            # Load model
            model = ml_model_manager.load_model(model_type, model_version)
            if model is None:
                raise ValueError(f"Could not load model: {model_type}")
            
            # Get model metadata
            if model_version:
                metadata = ml_model_manager.metadata.get(f"{model_type}_{model_version}")
            else:
                metadata = ml_model_manager.get_active_model(model_type)
            
            # Prepare results dictionary
            results = {
                'model_type': model_type,
                'model_version': metadata.version if metadata else 'unknown',
                'evaluation_timestamp': datetime.now().isoformat(),
                'dataset_info': {
                    'total_samples': len(X),
                    'positive_samples': int(np.sum(y)),
                    'negative_samples': int(len(y) - np.sum(y)),
                    'feature_count': X.shape[1]
                }
            }
            
            # Load scaler if needed
            scaler = ml_model_manager.load_model('feature_scaler')
            if scaler is not None:
                X_scaled = scaler.transform(X)
            else:
                X_scaled = X
                logger.warning("No scaler found, using unscaled features")
            
            # Basic predictions
            if hasattr(model, 'predict'):
                y_pred = model.predict(X_scaled)
                
                # Basic metrics
                basic_metrics = {
                    'accuracy': float(accuracy_score(y, y_pred)),
                    'precision': float(precision_score(y, y_pred, zero_division=0)),
                    'recall': float(recall_score(y, y_pred, zero_division=0)),
                    'f1_score': float(f1_score(y, y_pred, zero_division=0))
                }
                
                # ROC AUC if probability prediction is available
                if hasattr(model, 'predict_proba'):
                    y_proba = model.predict_proba(X_scaled)[:, 1]
                    basic_metrics['roc_auc'] = float(roc_auc_score(y, y_proba))
                elif hasattr(model, 'decision_function'):
                    y_scores = model.decision_function(X_scaled)
                    # Normalize scores for AUC calculation
                    y_scores_norm = (y_scores - y_scores.min()) / (y_scores.max() - y_scores.min())
                    basic_metrics['roc_auc'] = float(roc_auc_score(y, y_scores_norm))
                
                results['basic_metrics'] = basic_metrics
                
                # Confusion matrix
                cm = confusion_matrix(y, y_pred)
                results['confusion_matrix'] = {
                    'true_negatives': int(cm[0, 0]),
                    'false_positives': int(cm[0, 1]),
                    'false_negatives': int(cm[1, 0]),
                    'true_positives': int(cm[1, 1])
                }
                
                # Classification report
                class_report = classification_report(y, y_pred, output_dict=True, zero_division=0)
                results['classification_report'] = class_report
            
            # Cross-validation
            if hasattr(model, 'predict'):
                cv_results = self._perform_cross_validation(model, X_scaled, y, cv_folds)
                results['cross_validation'] = cv_results
            
            # Threshold evaluation
            threshold_results = self._evaluate_against_thresholds(basic_metrics)
            results['threshold_evaluation'] = threshold_results
            
            # Feature importance (if available)
            if hasattr(model, 'feature_importances_'):
                feature_importance = dict(zip(self.feature_names, model.feature_importances_))
                results['feature_importance'] = feature_importance
            
            # Model-specific evaluations
            if model_type == 'isolation_forest':
                results.update(self._evaluate_isolation_forest(model, X_scaled, y))
            elif model_type == 'ensemble':
                results.update(self._evaluate_ensemble_model(model, X_scaled, y))
            
            logger.info(f"Evaluation completed for {model_type}")
            return results
            
        except Exception as e:
            logger.error(f"Error evaluating model {model_type}: {e}")
            return {
                'model_type': model_type,
                'error': str(e),
                'evaluation_timestamp': datetime.now().isoformat()
            }
    
    def _perform_cross_validation(
        self,
        model,
        X: np.ndarray,
        y: np.ndarray,
        cv_folds: int
    ) -> Dict[str, Any]:
        """Perform cross-validation evaluation"""
        try:
            # Stratified K-Fold for balanced splits
            skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            
            # Cross-validation scores
            cv_scores = {}
            
            # Accuracy
            accuracy_scores = cross_val_score(model, X, y, cv=skf, scoring='accuracy')
            cv_scores['accuracy'] = {
                'mean': float(np.mean(accuracy_scores)),
                'std': float(np.std(accuracy_scores)),
                'scores': accuracy_scores.tolist()
            }
            
            # Precision
            precision_scores = cross_val_score(model, X, y, cv=skf, scoring='precision', zero_division=0)
            cv_scores['precision'] = {
                'mean': float(np.mean(precision_scores)),
                'std': float(np.std(precision_scores)),
                'scores': precision_scores.tolist()
            }
            
            # Recall
            recall_scores = cross_val_score(model, X, y, cv=skf, scoring='recall', zero_division=0)
            cv_scores['recall'] = {
                'mean': float(np.mean(recall_scores)),
                'std': float(np.std(recall_scores)),
                'scores': recall_scores.tolist()
            }
            
            # F1 Score
            f1_scores = cross_val_score(model, X, y, cv=skf, scoring='f1', zero_division=0)
            cv_scores['f1_score'] = {
                'mean': float(np.mean(f1_scores)),
                'std': float(np.std(f1_scores)),
                'scores': f1_scores.tolist()
            }
            
            # ROC AUC (if supported)
            try:
                roc_auc_scores = cross_val_score(model, X, y, cv=skf, scoring='roc_auc')
                cv_scores['roc_auc'] = {
                    'mean': float(np.mean(roc_auc_scores)),
                    'std': float(np.std(roc_auc_scores)),
                    'scores': roc_auc_scores.tolist()
                }
            except:
                pass  # Some models don't support probability prediction
            
            return {
                'cv_folds': cv_folds,
                'scores': cv_scores
            }
            
        except Exception as e:
            logger.error(f"Error in cross-validation: {e}")
            return {'error': str(e)}
    
    def _evaluate_against_thresholds(self, metrics: Dict[str, float]) -> Dict[str, Any]:
        """Evaluate metrics against configured thresholds"""
        threshold_results = {
            'passed': True,
            'failed_metrics': [],
            'threshold_checks': {}
        }
        
        threshold_mapping = {
            'min_accuracy': 'accuracy',
            'min_precision': 'precision',
            'min_recall': 'recall',
            'min_f1_score': 'f1_score',
            'min_roc_auc': 'roc_auc'
        }
        
        for threshold_name, metric_name in threshold_mapping.items():
            if threshold_name in self.thresholds and metric_name in metrics:
                threshold_value = self.thresholds[threshold_name]
                metric_value = metrics[metric_name]
                
                passed = metric_value >= threshold_value
                
                threshold_results['threshold_checks'][metric_name] = {
                    'threshold': threshold_value,
                    'actual': metric_value,
                    'passed': passed
                }
                
                if not passed:
                    threshold_results['passed'] = False
                    threshold_results['failed_metrics'].append(metric_name)
        
        return threshold_results
    
    def _evaluate_isolation_forest(self, model, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Specific evaluation for Isolation Forest models"""
        try:
            # Anomaly scores
            anomaly_scores = model.decision_function(X)
            
            # Predictions (-1 for anomaly, 1 for normal)
            predictions = model.predict(X)
            
            # Convert to binary (1 for anomaly, 0 for normal)
            binary_predictions = (predictions == -1).astype(int)
            
            return {
                'isolation_forest_metrics': {
                    'anomaly_score_mean': float(np.mean(anomaly_scores)),
                    'anomaly_score_std': float(np.std(anomaly_scores)),
                    'contamination_detected': float(np.mean(binary_predictions)),
                    'expected_contamination': model.contamination
                }
            }
            
        except Exception as e:
            logger.error(f"Error evaluating isolation forest: {e}")
            return {'isolation_forest_error': str(e)}
    
    def _evaluate_ensemble_model(self, model, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Specific evaluation for ensemble models"""
        try:
            # Extract individual models if available
            if isinstance(model, dict):
                behavioral_model = model.get('behavioral_model')
                isolation_model = model.get('isolation_model')
                weights = model.get('weights', {})
                
                ensemble_results = {
                    'ensemble_weights': weights,
                    'individual_model_performance': {}
                }
                
                # Evaluate individual models if available
                if behavioral_model and hasattr(behavioral_model, 'predict'):
                    y_pred_behavioral = behavioral_model.predict(X)
                    behavioral_metrics = {
                        'accuracy': float(accuracy_score(y, y_pred_behavioral)),
                        'precision': float(precision_score(y, y_pred_behavioral, zero_division=0)),
                        'recall': float(recall_score(y, y_pred_behavioral, zero_division=0)),
                        'f1_score': float(f1_score(y, y_pred_behavioral, zero_division=0))
                    }
                    ensemble_results['individual_model_performance']['behavioral'] = behavioral_metrics
                
                return {'ensemble_metrics': ensemble_results}
            
            return {}
            
        except Exception as e:
            logger.error(f"Error evaluating ensemble model: {e}")
            return {'ensemble_error': str(e)}
    
    def evaluate_all_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Evaluate all available models"""
        logger.info("Starting evaluation of all models...")
        
        all_results = {
            'evaluation_timestamp': datetime.now().isoformat(),
            'dataset_info': {
                'total_samples': len(X),
                'positive_samples': int(np.sum(y)),
                'negative_samples': int(len(y) - np.sum(y)),
                'feature_count': X.shape[1]
            },
            'model_evaluations': {}
        }
        
        # Get all available model types
        model_types = ['behavioral_analysis', 'isolation_forest', 'ensemble']
        
        for model_type in model_types:
            try:
                # Check if model exists
                active_model = ml_model_manager.get_active_model(model_type)
                if active_model:
                    results = self.evaluate_model(model_type, X, y)
                    all_results['model_evaluations'][model_type] = results
                else:
                    logger.warning(f"No active model found for type: {model_type}")
                    all_results['model_evaluations'][model_type] = {
                        'error': 'No active model found'
                    }
            except Exception as e:
                logger.error(f"Error evaluating {model_type}: {e}")
                all_results['model_evaluations'][model_type] = {
                    'error': str(e)
                }
        
        # Overall evaluation summary
        all_results['summary'] = self._generate_evaluation_summary(all_results['model_evaluations'])
        
        self.evaluation_results = all_results
        return all_results
    
    def _generate_evaluation_summary(self, model_evaluations: Dict) -> Dict[str, Any]:
        """Generate summary of all model evaluations"""
        summary = {
            'total_models_evaluated': 0,
            'models_passed_thresholds': 0,
            'models_failed_thresholds': 0,
            'best_performing_model': None,
            'overall_status': 'unknown'
        }
        
        best_f1_score = 0
        best_model = None
        
        for model_type, results in model_evaluations.items():
            if 'error' not in results:
                summary['total_models_evaluated'] += 1
                
                # Check threshold evaluation
                threshold_eval = results.get('threshold_evaluation', {})
                if threshold_eval.get('passed', False):
                    summary['models_passed_thresholds'] += 1
                else:
                    summary['models_failed_thresholds'] += 1
                
                # Track best performing model
                basic_metrics = results.get('basic_metrics', {})
                f1_score = basic_metrics.get('f1_score', 0)
                if f1_score > best_f1_score:
                    best_f1_score = f1_score
                    best_model = model_type
        
        summary['best_performing_model'] = best_model
        
        # Overall status
        if summary['models_failed_thresholds'] == 0 and summary['total_models_evaluated'] > 0:
            summary['overall_status'] = 'passed'
        elif summary['models_passed_thresholds'] > 0:
            summary['overall_status'] = 'partial'
        else:
            summary['overall_status'] = 'failed'
        
        return summary
    
    def generate_markdown_report(self, output_file: str = None) -> str:
        """Generate evaluation report in Markdown format"""
        if not self.evaluation_results:
            logger.error("No evaluation results available. Run evaluate_all_models() first.")
            return ""
        
        output_file = output_file or str(REPORTS_DIR / "ml_evaluation.md")
        
        try:
            with open(output_file, 'w') as f:
                f.write(self._create_markdown_content())
            
            logger.info(f"Evaluation report generated: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Error generating markdown report: {e}")
            return ""
    
    def _create_markdown_content(self) -> str:
        """Create markdown content for the evaluation report"""
        results = self.evaluation_results
        
        md_content = f"""# ML Model Evaluation Report

**Generated:** {results['evaluation_timestamp']}

## Dataset Information

- **Total Samples:** {results['dataset_info']['total_samples']:,}
- **Positive Samples (Malware):** {results['dataset_info']['positive_samples']:,}
- **Negative Samples (Benign):** {results['dataset_info']['negative_samples']:,}
- **Features:** {results['dataset_info']['feature_count']}

## Evaluation Summary

- **Models Evaluated:** {results['summary']['total_models_evaluated']}
- **Models Passed Thresholds:** {results['summary']['models_passed_thresholds']}
- **Models Failed Thresholds:** {results['summary']['models_failed_thresholds']}
- **Best Performing Model:** {results['summary']['best_performing_model'] or 'None'}
- **Overall Status:** {results['summary']['overall_status'].upper()}

"""
        
        # Individual model results
        for model_type, model_results in results['model_evaluations'].items():
            if 'error' in model_results:
                md_content += f"""## {model_type.replace('_', ' ').title()} Model

❌ **Error:** {model_results['error']}

"""
                continue
            
            basic_metrics = model_results.get('basic_metrics', {})
            threshold_eval = model_results.get('threshold_evaluation', {})
            
            status_icon = "✅" if threshold_eval.get('passed', False) else "❌"
            
            md_content += f"""## {model_type.replace('_', ' ').title()} Model

{status_icon} **Status:** {'PASSED' if threshold_eval.get('passed', False) else 'FAILED'}

### Basic Metrics

| Metric | Value |
|--------|-------|
| Accuracy | {basic_metrics.get('accuracy', 0):.4f} |
| Precision | {basic_metrics.get('precision', 0):.4f} |
| Recall | {basic_metrics.get('recall', 0):.4f} |
| F1-Score | {basic_metrics.get('f1_score', 0):.4f} |
| ROC AUC | {basic_metrics.get('roc_auc', 'N/A')} |

### Cross-Validation Results

"""
            
            cv_results = model_results.get('cross_validation', {})
            if 'scores' in cv_results:
                for metric, scores in cv_results['scores'].items():
                    md_content += f"- **{metric.replace('_', ' ').title()}:** {scores['mean']:.4f} ± {scores['std']:.4f}\n"
            
            md_content += "\n### Threshold Evaluation\n\n"
            
            if 'threshold_checks' in threshold_eval:
                for metric, check in threshold_eval['threshold_checks'].items():
                    status = "✅ PASS" if check['passed'] else "❌ FAIL"
                    md_content += f"- **{metric.replace('_', ' ').title()}:** {check['actual']:.4f} (threshold: {check['threshold']:.4f}) {status}\n"
            
            md_content += "\n"
        
        md_content += f"""
## Configuration Thresholds

"""
        
        for threshold_name, threshold_value in self.thresholds.items():
            md_content += f"- **{threshold_name.replace('_', ' ').title()}:** {threshold_value}\n"
        
        md_content += f"""

---
*Report generated by AntiV-AI ML Evaluation Framework*
"""
        
        return md_content

# Global instance
ml_evaluator = MLEvaluationFramework()

"""
aml_model_registry.py — Model Versioning and Metadata Tracking
=============================================================
Manages model versions, metadata, training history, and deployment tracking.
Provides enterprise-grade model governance for AML systems.
"""

import json
import os
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import hashlib
import shutil

logger = logging.getLogger(__name__)


class ModelRegistry:
    """
    Registry for managing AML model versions and metadata.
    
    Features:
    - Model version tracking
    - Training history
    - Performance metrics
    - Deployment tracking
    - Model rollback capability
    """
    
    def __init__(self, registry_dir: str = "model_registry"):
        """
        Initialize model registry.
        
        Args:
            registry_dir: Directory to store model registry data
        """
        self.registry_dir = Path(registry_dir)
        self.models_dir = self.registry_dir / "models"
        self.metadata_dir = self.registry_dir / "metadata"
        self.history_file = self.registry_dir / "training_history.json"
        self.current_model_file = self.registry_dir / "current_model.json"
        
        self._ensure_directories()
        self._load_history()
    
    def _ensure_directories(self) -> None:
        """Ensure registry directories exist."""
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_history(self) -> None:
        """Load training history from file."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self.training_history = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load training history: {e}")
                self.training_history = []
        else:
            self.training_history = []
    
    def _save_history(self) -> None:
        """Save training history to file."""
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.training_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save training history: {e}")
    
    def register_model(
        self,
        model_version: str,
        model_path: str,
        metadata: Dict[str, Any],
        performance_metrics: Dict[str, Any]
    ) -> str:
        """
        Register a new model version.
        
        Args:
            model_version: Version identifier (e.g., "3.0.0")
            model_path: Path to model file
            metadata: Model metadata
            performance_metrics: Performance metrics from training
            
        Returns:
            Model ID (timestamp-based)
        """
        model_id = f"{model_version}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
        
        # Create model directory
        model_dir = self.models_dir / model_id
        model_dir.mkdir(exist_ok=True)
        
        # Copy model to registry
        model_filename = os.path.basename(model_path)
        registered_model_path = model_dir / model_filename
        shutil.copy2(model_path, registered_model_path)
        
        # Also copy metadata file if it exists
        metadata_path = os.path.splitext(model_path)[0] + "_meta.json"
        if os.path.exists(metadata_path):
            shutil.copy2(metadata_path, model_dir / os.path.basename(metadata_path))
        
        # Create model record
        model_record = {
            "model_id": model_id,
            "model_version": model_version,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "model_path": str(registered_model_path),
            "metadata": metadata,
            "performance_metrics": performance_metrics,
            "is_deployed": False,
            "deployment_history": []
        }
        
        # Save model metadata
        metadata_file = self.metadata_dir / f"{model_id}.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(model_record, f, indent=2)
        
        # Add to training history
        self.training_history.append({
            "model_id": model_id,
            "model_version": model_version,
            "registered_at": model_record["registered_at"],
            "performance_metrics": performance_metrics
        })
        self._save_history()
        
        logger.info(f"Model registered: {model_id}")
        return model_id
    
    def deploy_model(self, model_id: str, deployed_by: str = "system") -> bool:
        """
        Deploy a model version.
        
        Args:
            model_id: Model ID to deploy
            deployed_by: User or system deploying the model
            
        Returns:
            True if successful, False otherwise
        """
        # Get model record
        model_record = self.get_model_record(model_id)
        if not model_record:
            logger.error(f"Model not found: {model_id}")
            return False
        
        # Undeploy current model if any
        current = self.get_current_model()
        if current:
            self.undeploy_model(current["model_id"])
        
        # Mark as deployed
        model_record["is_deployed"] = True
        model_record["deployed_at"] = datetime.now(timezone.utc).isoformat()
        model_record["deployed_by"] = deployed_by
        model_record["deployment_history"].append({
            "deployed_at": model_record["deployed_at"],
            "deployed_by": deployed_by,
            "action": "deployed"
        })
        
        # Save updated record
        metadata_file = self.metadata_dir / f"{model_id}.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(model_record, f, indent=2)
        
        # Update current model pointer
        with open(self.current_model_file, 'w', encoding='utf-8') as f:
            json.dump({
                "model_id": model_id,
                "deployed_at": model_record["deployed_at"],
                "deployed_by": deployed_by
            }, f, indent=2)
        
        logger.info(f"Model deployed: {model_id}")
        return True
    
    def undeploy_model(self, model_id: str) -> bool:
        """
        Undeploy a model version.
        
        Args:
            model_id: Model ID to undeploy
            
        Returns:
            True if successful, False otherwise
        """
        model_record = self.get_model_record(model_id)
        if not model_record:
            return False
        
        model_record["is_deployed"] = False
        model_record["undeployed_at"] = datetime.now(timezone.utc).isoformat()
        model_record["deployment_history"].append({
            "undeployed_at": model_record["undeployed_at"],
            "action": "undeployed"
        })
        
        # Save updated record
        metadata_file = self.metadata_dir / f"{model_id}.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(model_record, f, indent=2)
        
        # Clear current model pointer if this was the current model
        current = self.get_current_model()
        if current and current["model_id"] == model_id:
            if self.current_model_file.exists():
                self.current_model_file.unlink()
        
        logger.info(f"Model undeployed: {model_id}")
        return True
    
    def get_model_record(self, model_id: str) -> Optional[Dict[str, Any]]:
        """
        Get model record by ID.
        
        Args:
            model_id: Model ID
            
        Returns:
            Model record dictionary or None
        """
        metadata_file = self.metadata_dir / f"{model_id}.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load model record: {e}")
        return None
    
    def get_current_model(self) -> Optional[Dict[str, Any]]:
        """
        Get currently deployed model.
        
        Returns:
            Current model record or None
        """
        if not self.current_model_file.exists():
            return None
        
        try:
            with open(self.current_model_file, 'r', encoding='utf-8') as f:
                current_info = json.load(f)
            model_id = current_info.get("model_id")
            return self.get_model_record(model_id)
        except Exception as e:
            logger.error(f"Failed to get current model: {e}")
            return None
    
    def list_models(self, deployed_only: bool = False) -> List[Dict[str, Any]]:
        """
        List all registered models.
        
        Args:
            deployed_only: If True, only return deployed models
            
        Returns:
            List of model records
        """
        models = []
        
        for metadata_file in self.metadata_dir.glob("*.json"):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    record = json.load(f)
                
                if deployed_only and not record.get("is_deployed", False):
                    continue
                
                models.append(record)
            except Exception as e:
                logger.error(f"Failed to load model record {metadata_file}: {e}")
        
        # Sort by registration time (newest first)
        models.sort(key=lambda x: x.get("registered_at", ""), reverse=True)
        
        return models
    
    def get_training_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get training history.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            List of training records
        """
        return self.training_history[-limit:]
    
    def rollback_to_model(self, model_id: str, rolled_back_by: str = "system") -> bool:
        """
        Rollback to a previous model version.
        
        Args:
            model_id: Model ID to rollback to
            rolled_back_by: User or system performing rollback
            
        Returns:
            True if successful, False otherwise
        """
        model_record = self.get_model_record(model_id)
        if not model_record:
            logger.error(f"Cannot rollback: model not found: {model_id}")
            return False
        
        # Deploy the target model
        success = self.deploy_model(model_id, rolled_back_by)
        
        if success:
            # Add rollback note to deployment history
            model_record["deployment_history"].append({
                "rolled_back_at": datetime.now(timezone.utc).isoformat(),
                "rolled_back_by": rolled_back_by,
                "action": "rollback"
            })
            
            metadata_file = self.metadata_dir / f"{model_id}.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(model_record, f, indent=2)
            
            logger.info(f"Rollback successful to: {model_id}")
        
        return success
    
    def delete_model(self, model_id: str) -> bool:
        """
        Delete a model from registry (only if not deployed).
        
        Args:
            model_id: Model ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        model_record = self.get_model_record(model_id)
        if not model_record:
            return False
        
        if model_record.get("is_deployed", False):
            logger.error(f"Cannot delete deployed model: {model_id}")
            return False
        
        # Delete model files
        model_dir = self.models_dir / model_id
        if model_dir.exists():
            shutil.rmtree(model_dir)
        
        # Delete metadata
        metadata_file = self.metadata_dir / f"{model_id}.json"
        if metadata_file.exists():
            metadata_file.unlink()
        
        # Remove from history
        self.training_history = [
            record for record in self.training_history
            if record.get("model_id") != model_id
        ]
        self._save_history()
        
        logger.info(f"Model deleted: {model_id}")
        return True
    
    def get_model_comparison(self, model_ids: List[str]) -> Dict[str, Any]:
        """
        Compare multiple models.
        
        Args:
            model_ids: List of model IDs to compare
            
        Returns:
            Comparison dictionary
        """
        models = []
        for model_id in model_ids:
            record = self.get_model_record(model_id)
            if record:
                models.append(record)
        
        if len(models) < 2:
            return {"error": "Need at least 2 models to compare"}
        
        comparison = {
            "models": models,
            "metrics_comparison": {}
        }
        
        # Compare performance metrics
        metric_names = set()
        for model in models:
            metrics = model.get("performance_metrics", {})
            metric_names.update(metrics.keys())
        
        for metric in metric_names:
            comparison["metrics_comparison"][metric] = {
                model["model_id"]: model.get("performance_metrics", {}).get(metric)
                for model in models
            }
        
        return comparison
    
    def calculate_model_hash(self, model_path: str) -> str:
        """
        Calculate hash of model file for integrity checking.
        
        Args:
            model_path: Path to model file
            
        Returns:
            SHA256 hash string
        """
        sha256_hash = hashlib.sha256()
        
        with open(model_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()


# Global registry instance
_default_registry = ModelRegistry()


def register_model(
    model_version: str,
    model_path: str,
    metadata: Dict[str, Any],
    performance_metrics: Dict[str, Any]
) -> str:
    """Register a new model."""
    return _default_registry.register_model(model_version, model_path, metadata, performance_metrics)


def deploy_model(model_id: str, deployed_by: str = "system") -> bool:
    """Deploy a model."""
    return _default_registry.deploy_model(model_id, deployed_by)


def get_current_model() -> Optional[Dict[str, Any]]:
    """Get currently deployed model."""
    return _default_registry.get_current_model()


def list_models(deployed_only: bool = False) -> List[Dict[str, Any]]:
    """List all models."""
    return _default_registry.list_models(deployed_only)


def rollback_to_model(model_id: str, rolled_back_by: str = "system") -> bool:
    """Rollback to a previous model."""
    return _default_registry.rollback_to_model(model_id, rolled_back_by)

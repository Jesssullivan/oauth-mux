//! Gates access to the retained startup model catalog on current managed provider requirements.

use std::sync::Arc;

use codex_core::config::Config;
use codex_models_manager::manager::RefreshStrategy;
use codex_models_manager::manager::SharedModelsManager;
use codex_protocol::openai_models::ModelPreset;

use crate::config_manager::ConfigManager;

/// Checks the retained catalog route before model/list and background refreshes.
pub(crate) struct ModelCatalog {
    config_manager: ConfigManager,
    config: Arc<Config>,
    models_manager: SharedModelsManager,
}

impl ModelCatalog {
    pub(crate) fn new(
        config_manager: ConfigManager,
        config: Arc<Config>,
        models_manager: SharedModelsManager,
    ) -> Self {
        Self {
            config_manager,
            config,
            models_manager,
        }
    }

    pub(crate) async fn list_models(
        &self,
        refresh_strategy: RefreshStrategy,
    ) -> std::io::Result<Vec<ModelPreset>> {
        // Check before consulting even a warm cache, just as turn admission checks
        // the retained session route before using it.
        if self.config.omux_broker_config()?.is_some()
            || codex_core::auth_broker::any_ambient_blocked()
            || self.models_manager.is_broker_descriptive()
        {
            // This bundled catalog describes models, not account entitlements. Do not
            // refresh it through unrelated canonical native auth or filter it by that auth.
            let mut catalog = codex_models_manager::bundled_models_response()
                .map_err(|_| std::io::Error::other("bundled model catalog is invalid"))?;
            catalog.models.sort_by_key(|model| model.priority);
            let mut presets: Vec<ModelPreset> =
                catalog.models.into_iter().map(Into::into).collect();
            ModelPreset::mark_default_by_picker_visibility(&mut presets);
            return Ok(presets);
        }
        let Some(_ambient_activity) =
            codex_core::auth_broker::try_acquire_threadless_ambient_activity()
        else {
            return Err(std::io::Error::other(
                "native model discovery is unavailable while Omux manages a thread",
            ));
        };
        self.config_manager
            .check_thread_model_provider(&self.config)
            .await?;
        Ok(self
            .models_manager
            .list_models(refresh_strategy, self.config.http_client_factory())
            .await)
    }
}

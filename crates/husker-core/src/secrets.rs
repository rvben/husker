use super::*;

impl<B: VmmBackend> HuskerCore<B> {
    /// Create a new encrypted secret.
    pub fn create_secret(&self, req: CreateSecretRequest) -> Result<SecretMetadata, CoreError> {
        validate_resource_name("secret", &req.name)?;

        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let (ciphertext, nonce) = encrypt_secret(&key, req.value.as_bytes())?;
        let now = chrono::Utc::now();
        let record = SecretRecord {
            id: Uuid::new_v4(),
            name: req.name,
            ciphertext,
            nonce,
            created_at: now,
            updated_at: now,
        };

        self.state.insert_secret(&record).map_err(|e| match e {
            husker_state::StateError::SecretAlreadyExists(name) => {
                CoreError::SecretAlreadyExists(name)
            }
            other => CoreError::State(other),
        })?;

        Ok(secret_to_metadata(record))
    }

    /// List secret metadata (never includes plaintext values).
    pub fn list_secrets(&self) -> Result<Vec<SecretMetadata>, CoreError> {
        Ok(self
            .state
            .list_secrets()?
            .into_iter()
            .map(secret_to_metadata)
            .collect())
    }

    /// Get metadata for a secret by name.
    pub fn get_secret(&self, name: &str) -> Result<SecretMetadata, CoreError> {
        let record = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        Ok(secret_to_metadata(record))
    }

    /// Reveal decrypted plaintext for a secret by name.
    pub fn reveal_secret(&self, name: &str) -> Result<RevealedSecret, CoreError> {
        let record = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let plaintext = decrypt_secret(&key, &record.nonce, &record.ciphertext)?;
        let value = String::from_utf8(plaintext)
            .map_err(|e| CoreError::SecretCrypto(format!("secret is not valid UTF-8: {e}")))?;

        Ok(RevealedSecret {
            name: record.name,
            value,
            updated_at: record.updated_at,
        })
    }

    /// Rotate (replace) the value of an existing secret.
    pub fn rotate_secret(
        &self,
        name: &str,
        req: RotateSecretRequest,
    ) -> Result<SecretMetadata, CoreError> {
        let existing = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        let key = load_or_create_secret_key(&self.storage.data_dir)?;
        let (ciphertext, nonce) = encrypt_secret(&key, req.value.as_bytes())?;
        self.state
            .update_secret_payload(existing.id, &ciphertext, &nonce)
            .map_err(|e| match e {
                husker_state::StateError::SecretNotFound(_) => {
                    CoreError::SecretNotFound(name.into())
                }
                other => CoreError::State(other),
            })?;
        self.get_secret(name)
    }

    /// Delete a secret by name.
    pub fn delete_secret(&self, name: &str) -> Result<(), CoreError> {
        let secret = self.state.get_secret_by_name(name).map_err(|e| match e {
            husker_state::StateError::SecretNotFoundByName(_) => {
                CoreError::SecretNotFound(name.into())
            }
            other => CoreError::State(other),
        })?;
        self.state.delete_secret(secret.id).map_err(|e| match e {
            husker_state::StateError::SecretNotFound(_) => CoreError::SecretNotFound(name.into()),
            other => CoreError::State(other),
        })
    }
}

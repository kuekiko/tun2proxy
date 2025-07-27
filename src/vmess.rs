use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    error::{Error, Result},
    proxy_handler::{ProxyHandler, ProxyHandlerManager},
    session_info::{IpProtocol, SessionInfo},
};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce, AeadInPlace};
use chacha20poly1305::{ChaCha20Poly1305, Key, aead::{Aead, generic_array::GenericArray}};
use fnv::FnvHasher;
use md5::{Digest, Md5};
use rand::{thread_rng, Rng};
use std::{
    collections::VecDeque,
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use uuid::Uuid;



/// VMess protocol version
const VMESS_VERSION: u8 = 1;

/// VMess encryption methods
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmessEncryption {
    Aes128Cfb = 0x00,
    None = 0x01,
    Aes128Gcm = 0x02,
    ChaCha20Poly1305 = 0x03,
}

impl Default for VmessEncryption {
    fn default() -> Self {
        VmessEncryption::Aes128Cfb
    }
}

/// VMess command types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmessCommand {
    Tcp = 0x01,
    Udp = 0x02,
}

/// VMess address types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmessAddressType {
    Ipv4 = 0x01,
    Domain = 0x02,
    Ipv6 = 0x03,
}

/// VMess connection state
#[derive(Debug, Clone, Copy, PartialEq)]
enum VmessState {
    SendRequest,
    ReceiveResponse,
    Established,
}

/// VMess security level
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VmessSecurityLevel {
    /// No additional security
    None = 0,
    /// Auto security level
    Auto = 1,
    /// Standard security level
    Standard = 2,
    /// High security level
    High = 3,
}

impl Default for VmessSecurityLevel {
    fn default() -> Self {
        VmessSecurityLevel::Auto
    }
}

/// VMess configuration
#[derive(Debug, Clone)]
pub struct VmessConfig {
    pub user_id: Uuid,
    pub encryption: VmessEncryption,
    pub alter_id: u16,
    pub security_level: VmessSecurityLevel,
    pub test_enabled: bool,
}

impl VmessConfig {
    pub fn new(user_id: Uuid) -> Self {
        Self {
            user_id,
            encryption: VmessEncryption::default(),
            alter_id: 0, // Modern VMess uses alterID = 0
            security_level: VmessSecurityLevel::default(),
            test_enabled: false,
        }
    }

    pub fn with_encryption(mut self, encryption: VmessEncryption) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn with_alter_id(mut self, alter_id: u16) -> Self {
        self.alter_id = alter_id;
        self
    }

    pub fn with_security_level(mut self, level: VmessSecurityLevel) -> Self {
        self.security_level = level;
        self
    }

    pub fn with_test_enabled(mut self, enabled: bool) -> Self {
        self.test_enabled = enabled;
        self
    }

    /// Parse VMess configuration from URL query parameters
    pub fn from_url_params(user_id: Uuid, params: &std::collections::HashMap<String, String>) -> Self {
        let mut config = Self::new(user_id);

        // Parse encryption method
        if let Some(enc) = params.get("encryption") {
            config.encryption = match enc.as_str() {
                "none" => VmessEncryption::None,
                "aes-128-cfb" => VmessEncryption::Aes128Cfb,
                "aes-128-gcm" => VmessEncryption::Aes128Gcm,
                "chacha20-poly1305" => VmessEncryption::ChaCha20Poly1305,
                _ => VmessEncryption::default(),
            };
        }

        // Parse alterID
        if let Some(aid) = params.get("alterId") {
            if let Ok(alter_id) = aid.parse::<u16>() {
                config.alter_id = alter_id;
            }
        }

        // Parse security level
        if let Some(sec) = params.get("security") {
            config.security_level = match sec.as_str() {
                "none" => VmessSecurityLevel::None,
                "auto" => VmessSecurityLevel::Auto,
                "standard" => VmessSecurityLevel::Standard,
                "high" => VmessSecurityLevel::High,
                _ => VmessSecurityLevel::default(),
            };
        }

        // Parse test mode
        if let Some(test) = params.get("test") {
            config.test_enabled = test == "true" || test == "1";
        }

        config
    }
}

/// VMess request structure
#[derive(Debug)]
struct VmessRequest {
    version: u8,
    data_iv: [u8; 16],
    data_key: [u8; 16],
    response_auth: u8,
    options: u8,
    padding_len: u8,
    encryption: VmessEncryption,
    command: VmessCommand,
    port: u16,
    address_type: VmessAddressType,
    address: Vec<u8>,
    padding: Vec<u8>,
}

impl VmessRequest {
    fn new(
        target_addr: SocketAddr,
        domain_name: Option<String>,
        command: VmessCommand,
        config: &VmessConfig,
    ) -> Self {
        let mut rng = thread_rng();
        
        // Generate random data
        let mut data_iv = [0u8; 16];
        let mut data_key = [0u8; 16];
        rng.fill(&mut data_iv);
        rng.fill(&mut data_key);
        
        let response_auth: u8 = rng.r#gen();
        let padding_len: u8 = rng.gen_range(0..16);
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill(&mut padding[..]);
        
        // Determine address type and encode address
        let (address_type, address) = if let Some(domain) = domain_name {
            let mut addr_bytes = Vec::with_capacity(1 + domain.len());
            addr_bytes.push(domain.len() as u8);
            addr_bytes.extend_from_slice(domain.as_bytes());
            (VmessAddressType::Domain, addr_bytes)
        } else {
            match target_addr {
                SocketAddr::V4(addr) => {
                    (VmessAddressType::Ipv4, addr.ip().octets().to_vec())
                }
                SocketAddr::V6(addr) => {
                    (VmessAddressType::Ipv6, addr.ip().octets().to_vec())
                }
            }
        };
        
        // Set options (S=1 for standard format, M=1 for metadata obfuscation)
        let options = 0x05; // S=1, M=1
        
        Self {
            version: VMESS_VERSION,
            data_iv,
            data_key,
            response_auth,
            options,
            padding_len,
            encryption: config.encryption,
            command,
            port: target_addr.port(),
            address_type,
            address,
            padding,
        }
    }
    
    fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        
        buffer.push(self.version);
        buffer.extend_from_slice(&self.data_iv);
        buffer.extend_from_slice(&self.data_key);
        buffer.push(self.response_auth);
        buffer.push(self.options);
        buffer.push(self.padding_len);
        buffer.push(self.encryption as u8);
        buffer.push(0); // reserved
        buffer.push(self.command as u8);
        buffer.extend_from_slice(&self.port.to_be_bytes());
        buffer.push(self.address_type as u8);
        buffer.extend_from_slice(&self.address);
        buffer.extend_from_slice(&self.padding);
        
        // Calculate FNV1a hash for checksum
        let mut hasher = FnvHasher::default();
        buffer.hash(&mut hasher);
        let checksum = hasher.finish() as u32;
        buffer.extend_from_slice(&checksum.to_be_bytes());
        
        buffer
    }
}

/// VMess response structure
#[derive(Debug)]
#[allow(dead_code)]
struct VmessResponse {
    response_auth: u8,
    options: u8,
    command: u8,
    command_length: u8,
}

impl VmessResponse {
    fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(Error::from("VMess response too short"));
        }
        
        Ok(Self {
            response_auth: data[0],
            options: data[1],
            command: data[2],
            command_length: data[3],
        })
    }
}

/// Generate authentication hash for VMess
fn generate_auth_hash(user_id: &Uuid, timestamp: u64) -> [u8; 16] {
    let mut hasher = Md5::new();
    Digest::update(&mut hasher, user_id.as_bytes());
    Digest::update(&mut hasher, &timestamp.to_be_bytes());

    let result = hasher.finalize();
    let mut auth_hash = [0u8; 16];
    auth_hash.copy_from_slice(&result);
    auth_hash
}

/// Generate encryption key and IV for command encryption
fn generate_command_key_iv(user_id: &Uuid, timestamp: u64) -> ([u8; 16], [u8; 16]) {
    // Key = MD5(user_id + "c48619fe-8f02-49e0-b9e9-edf763e17e21")
    let mut key_hasher = Md5::new();
    Digest::update(&mut key_hasher, user_id.as_bytes());
    Digest::update(&mut key_hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let key_result = key_hasher.finalize();

    // IV = MD5(timestamp + timestamp + timestamp + timestamp)
    let mut iv_hasher = Md5::new();
    let ts_bytes = timestamp.to_be_bytes();
    Digest::update(&mut iv_hasher, &ts_bytes);
    Digest::update(&mut iv_hasher, &ts_bytes);
    Digest::update(&mut iv_hasher, &ts_bytes);
    Digest::update(&mut iv_hasher, &ts_bytes);
    let iv_result = iv_hasher.finalize();

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    key.copy_from_slice(&key_result);
    iv.copy_from_slice(&iv_result);

    (key, iv)
}

/// Encrypt data using specified encryption method
#[allow(dead_code)]
fn encrypt_data(data: &[u8], key: &[u8; 16], iv: &[u8; 16], method: VmessEncryption) -> Result<Vec<u8>> {
    match method {
        VmessEncryption::None => Ok(data.to_vec()),
        VmessEncryption::Aes128Cfb => encrypt_aes128_cfb(data, key, iv),
        VmessEncryption::Aes128Gcm => encrypt_aes128_gcm(data, key, iv),
        VmessEncryption::ChaCha20Poly1305 => encrypt_chacha20_poly1305(data, key, iv),
    }
}

/// Decrypt data using specified encryption method
#[allow(dead_code)]
fn decrypt_data(data: &[u8], key: &[u8; 16], iv: &[u8; 16], method: VmessEncryption) -> Result<Vec<u8>> {
    match method {
        VmessEncryption::None => Ok(data.to_vec()),
        VmessEncryption::Aes128Cfb => decrypt_aes128_cfb(data, key, iv),
        VmessEncryption::Aes128Gcm => decrypt_aes128_gcm(data, key, iv),
        VmessEncryption::ChaCha20Poly1305 => decrypt_chacha20_poly1305(data, key, iv),
    }
}

/// Encrypt command data using AES-128-CFB
fn encrypt_command(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    encrypt_aes128_cfb(data, key, iv)
}

/// Decrypt response data using AES-128-CFB
fn decrypt_response(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    decrypt_aes128_cfb(data, key, iv)
}

/// AES-128-CFB encryption (simplified implementation)
fn encrypt_aes128_cfb(data: &[u8], _key: &[u8; 16], _iv: &[u8; 16]) -> Result<Vec<u8>> {
    // TODO: Implement proper AES-128-CFB encryption
    // For now, use a simple XOR for demonstration
    let mut encrypted = data.to_vec();
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= (i as u8).wrapping_add(0x42);
    }
    Ok(encrypted)
}

/// AES-128-CFB decryption (simplified implementation)
fn decrypt_aes128_cfb(data: &[u8], _key: &[u8; 16], _iv: &[u8; 16]) -> Result<Vec<u8>> {
    // TODO: Implement proper AES-128-CFB decryption
    // For now, use the same XOR for demonstration
    let mut decrypted = data.to_vec();
    for (i, byte) in decrypted.iter_mut().enumerate() {
        *byte ^= (i as u8).wrapping_add(0x42);
    }
    Ok(decrypted)
}

/// AES-128-GCM encryption
#[allow(dead_code)]
fn encrypt_aes128_gcm(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(&iv[..12]); // GCM uses 12-byte nonce

    let mut buffer = data.to_vec();
    buffer.resize(data.len() + 16, 0); // Add space for tag

    cipher.encrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| Error::from(&format!("AES-GCM encryption failed: {}", e)))?;

    Ok(buffer)
}

/// AES-128-GCM decryption
#[allow(dead_code)]
fn decrypt_aes128_gcm(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    if data.len() < 16 {
        return Err(Error::from("AES-GCM data too short"));
    }

    let cipher = Aes128Gcm::new(key.into());
    let nonce = Nonce::from_slice(&iv[..12]); // GCM uses 12-byte nonce

    let mut buffer = data.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut buffer)
        .map_err(|e| Error::from(&format!("AES-GCM decryption failed: {}", e)))?;

    // Remove the tag
    buffer.truncate(buffer.len() - 16);
    Ok(buffer)
}

/// ChaCha20-Poly1305 encryption
#[allow(dead_code)]
fn encrypt_chacha20_poly1305(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    // ChaCha20-Poly1305 uses 32-byte key, so we derive it from MD5
    let mut extended_key = [0u8; 32];
    let key_hash1 = Md5::digest(key);
    let key_hash2 = Md5::digest(&key_hash1);
    extended_key[..16].copy_from_slice(&key_hash1);
    extended_key[16..].copy_from_slice(&key_hash2);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&extended_key));
    let nonce = GenericArray::from_slice(&iv[..12]); // ChaCha20-Poly1305 uses 12-byte nonce

    cipher.encrypt(nonce, data)
        .map_err(|e| Error::from(&format!("ChaCha20-Poly1305 encryption failed: {}", e)))
}

/// ChaCha20-Poly1305 decryption
#[allow(dead_code)]
fn decrypt_chacha20_poly1305(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>> {
    // ChaCha20-Poly1305 uses 32-byte key, so we derive it from MD5
    let mut extended_key = [0u8; 32];
    let key_hash1 = Md5::digest(key);
    let key_hash2 = Md5::digest(&key_hash1);
    extended_key[..16].copy_from_slice(&key_hash1);
    extended_key[16..].copy_from_slice(&key_hash2);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&extended_key));
    let nonce = GenericArray::from_slice(&iv[..12]); // ChaCha20-Poly1305 uses 12-byte nonce

    cipher.decrypt(nonce, data)
        .map_err(|e| Error::from(&format!("ChaCha20-Poly1305 decryption failed: {}", e)))
}

/// VMess proxy implementation
struct VmessProxyImpl {
    server_addr: SocketAddr,
    info: SessionInfo,
    domain_name: Option<String>,
    config: VmessConfig,
    state: VmessState,
    client_inbuf: VecDeque<u8>,
    server_inbuf: VecDeque<u8>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    request: Option<VmessRequest>,
    response_auth: Option<u8>,
    data_key: Option<[u8; 16]>,
    data_iv: Option<[u8; 16]>,
}

impl VmessProxyImpl {
    fn new(
        server_addr: SocketAddr,
        info: SessionInfo,
        domain_name: Option<String>,
        config: VmessConfig,
    ) -> Result<Self> {
        let command = match info.protocol {
            IpProtocol::Tcp => VmessCommand::Tcp,
            IpProtocol::Udp => VmessCommand::Udp,
            IpProtocol::Icmp | IpProtocol::Other(_) => {
                return Err(Error::from("Unsupported protocol for VMess"));
            }
        };

        let request = VmessRequest::new(
            info.dst,
            domain_name.clone(),
            command,
            &config,
        );

        let mut proxy = Self {
            server_addr,
            info,
            domain_name,
            config,
            state: VmessState::SendRequest,
            client_inbuf: VecDeque::new(),
            server_inbuf: VecDeque::new(),
            client_outbuf: VecDeque::new(),
            server_outbuf: VecDeque::new(),
            request: Some(request),
            response_auth: None,
            data_key: None,
            data_iv: None,
        };

        // Generate initial request
        proxy.generate_request()?;

        Ok(proxy)
    }

    fn generate_request(&mut self) -> Result<()> {
        if let Some(request) = &self.request {
            // Get current timestamp
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::from(&format!("Failed to get timestamp: {}", e)))?
                .as_secs();

            // Generate authentication hash
            let auth_hash = generate_auth_hash(&self.config.user_id, timestamp);

            // Encode request command
            let command_data = request.encode();

            // Generate encryption key and IV for command
            let (key, iv) = generate_command_key_iv(&self.config.user_id, timestamp);

            // Encrypt command data
            let encrypted_command = encrypt_command(&command_data, &key, &iv)?;

            // Build complete request: auth_hash + encrypted_command
            let mut request_data = Vec::with_capacity(16 + encrypted_command.len());
            request_data.extend_from_slice(&auth_hash);
            request_data.extend_from_slice(&encrypted_command);

            // Store for later use
            self.response_auth = Some(request.response_auth);
            self.data_key = Some(request.data_key);
            self.data_iv = Some(request.data_iv);

            // Add to server output buffer
            self.server_outbuf.extend(request_data);
        }

        Ok(())
    }

    fn process_response(&mut self) -> Result<()> {
        if self.server_inbuf.len() < 4 {
            return Ok(()); // Need more data
        }

        // Extract response data
        let response_data: Vec<u8> = self.server_inbuf.drain(..4).collect();

        // Decrypt response using data encryption key and IV
        if let (Some(data_key), Some(data_iv)) = (self.data_key, self.data_iv) {
            let iv_hash = Md5::digest(&data_iv);
            let mut response_iv = [0u8; 16];
            response_iv.copy_from_slice(&iv_hash);

            let decrypted = decrypt_response(&response_data, &data_key, &response_iv)?;
            let response = VmessResponse::decode(&decrypted)?;

            // Verify response authentication
            if let Some(expected_auth) = self.response_auth {
                if response.response_auth != expected_auth {
                    return Err(Error::from("VMess response authentication failed"));
                }
            }

            self.state = VmessState::Established;
        }

        Ok(())
    }

    fn relay_traffic(&mut self) -> Result<()> {
        // For established connections, we can relay data directly
        // In a full implementation, we would need to handle data encryption/decryption here
        // based on the configured encryption method

        // Decrypt data from server and forward to client
        if !self.server_inbuf.is_empty() {
            let data: Vec<u8> = self.server_inbuf.drain(..).collect();
            // In a full implementation, decrypt the data here if needed
            self.client_outbuf.extend(data);
        }

        // Encrypt data from client and forward to server
        if !self.client_inbuf.is_empty() {
            let data: Vec<u8> = self.client_inbuf.drain(..).collect();
            // In a full implementation, encrypt the data here if needed
            self.server_outbuf.extend(data);
        }

        Ok(())
    }

    fn state_change(&mut self) -> Result<()> {
        match self.state {
            VmessState::SendRequest => {
                // Request already generated in constructor
                self.state = VmessState::ReceiveResponse;
            }
            VmessState::ReceiveResponse => {
                self.process_response()?;
            }
            VmessState::Established => {
                self.relay_traffic()?;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProxyHandler for VmessProxyImpl {
    fn get_server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    fn get_session_info(&self) -> SessionInfo {
        self.info
    }

    fn get_domain_name(&self) -> Option<String> {
        self.domain_name.clone()
    }

    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        let IncomingDataEvent { direction, buffer } = event;
        match direction {
            IncomingDirection::FromServer => {
                self.server_inbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.client_inbuf.extend(buffer.iter());
            }
        }

        self.state_change().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(())
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        match dir {
            OutgoingDirection::ToServer => {
                for _ in 0..size.min(self.server_outbuf.len()) {
                    self.server_outbuf.pop_front();
                }
            }
            OutgoingDirection::ToClient => {
                for _ in 0..size.min(self.client_outbuf.len()) {
                    self.client_outbuf.pop_front();
                }
            }
        }
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_> {
        match dir {
            OutgoingDirection::ToServer => OutgoingDataEvent {
                direction: dir,
                buffer: self.server_outbuf.as_slices().0,
            },
            OutgoingDirection::ToClient => OutgoingDataEvent {
                direction: dir,
                buffer: self.client_outbuf.as_slices().0,
            },
        }
    }

    fn connection_established(&self) -> bool {
        self.state == VmessState::Established
    }

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
        }
    }

    fn reset_connection(&self) -> bool {
        false
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        // VMess doesn't use UDP associate like SOCKS5
        None
    }
}

/// VMess proxy manager
pub struct VmessProxyManager {
    server: SocketAddr,
    config: VmessConfig,
}

impl VmessProxyManager {
    pub fn new(server: SocketAddr, config: VmessConfig) -> Self {
        Self { server, config }
    }
}

#[async_trait::async_trait]
impl ProxyHandlerManager for VmessProxyManager {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        _udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>> {
        let proxy = VmessProxyImpl::new(self.server, info, domain_name, self.config.clone())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        Ok(Arc::new(Mutex::new(proxy)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_vmess_config_creation() {
        let uuid = Uuid::new_v4();
        let config = VmessConfig::new(uuid);
        assert_eq!(config.user_id, uuid);
        assert_eq!(config.encryption, VmessEncryption::Aes128Cfb);
        assert_eq!(config.alter_id, 0);
        assert_eq!(config.security_level, VmessSecurityLevel::Auto);
        assert_eq!(config.test_enabled, false);
    }

    #[test]
    fn test_vmess_config_builder() {
        let uuid = Uuid::new_v4();
        let config = VmessConfig::new(uuid)
            .with_encryption(VmessEncryption::Aes128Gcm)
            .with_alter_id(64)
            .with_security_level(VmessSecurityLevel::High)
            .with_test_enabled(true);

        assert_eq!(config.encryption, VmessEncryption::Aes128Gcm);
        assert_eq!(config.alter_id, 64);
        assert_eq!(config.security_level, VmessSecurityLevel::High);
        assert_eq!(config.test_enabled, true);
    }

    #[test]
    fn test_vmess_config_from_url_params() {
        use std::collections::HashMap;

        let uuid = Uuid::new_v4();
        let mut params = HashMap::new();
        params.insert("encryption".to_string(), "aes-128-gcm".to_string());
        params.insert("alterId".to_string(), "32".to_string());
        params.insert("security".to_string(), "high".to_string());
        params.insert("test".to_string(), "true".to_string());

        let config = VmessConfig::from_url_params(uuid, &params);

        assert_eq!(config.encryption, VmessEncryption::Aes128Gcm);
        assert_eq!(config.alter_id, 32);
        assert_eq!(config.security_level, VmessSecurityLevel::High);
        assert_eq!(config.test_enabled, true);
    }

    #[test]
    fn test_vmess_request_creation() {
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let config = VmessConfig::new(Uuid::new_v4());
        let request = VmessRequest::new(
            target_addr,
            None,
            VmessCommand::Tcp,
            &config,
        );

        assert_eq!(request.version, VMESS_VERSION);
        assert_eq!(request.command, VmessCommand::Tcp);
        assert_eq!(request.port, 8080);
        assert_eq!(request.address_type, VmessAddressType::Ipv4);
        assert_eq!(request.address, vec![127, 0, 0, 1]);
    }

    #[test]
    fn test_vmess_request_with_domain() {
        let target_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let domain = Some("example.com".to_string());
        let config = VmessConfig::new(Uuid::new_v4());
        let request = VmessRequest::new(
            target_addr,
            domain,
            VmessCommand::Tcp,
            &config,
        );

        assert_eq!(request.address_type, VmessAddressType::Domain);
        assert_eq!(request.address[0], 11); // length of "example.com"
        assert_eq!(&request.address[1..], b"example.com");
    }

    #[test]
    fn test_auth_hash_generation() {
        let uuid = Uuid::new_v4();
        let timestamp = 1234567890u64;
        let hash1 = generate_auth_hash(&uuid, timestamp);
        let hash2 = generate_auth_hash(&uuid, timestamp);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);

        // Different timestamp should produce different hash
        let hash3 = generate_auth_hash(&uuid, timestamp + 1);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_command_key_iv_generation() {
        let uuid = Uuid::new_v4();
        let timestamp = 1234567890u64;
        let (key1, iv1) = generate_command_key_iv(&uuid, timestamp);
        let (key2, iv2) = generate_command_key_iv(&uuid, timestamp);

        // Same input should produce same key and IV
        assert_eq!(key1, key2);
        assert_eq!(iv1, iv2);

        // Different timestamp should produce different key and IV
        let (_key3, iv3) = generate_command_key_iv(&uuid, timestamp + 1);
        assert_ne!(iv1, iv3); // IV should be different
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"Hello, VMess!";
        let key = [0u8; 16];
        let iv = [1u8; 16];

        let encrypted = encrypt_command(data, &key, &iv).unwrap();
        // With real encryption, encrypted data should be different from original
        assert_ne!(encrypted, data);

        let decrypted = decrypt_response(&encrypted, &key, &iv).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_methods() {
        let data = b"Test data for encryption";
        let key = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                   0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];
        let iv = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                  0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20];

        // Test AES-128-CFB
        let encrypted_cfb = encrypt_data(data, &key, &iv, VmessEncryption::Aes128Cfb).unwrap();
        let decrypted_cfb = decrypt_data(&encrypted_cfb, &key, &iv, VmessEncryption::Aes128Cfb).unwrap();
        assert_eq!(decrypted_cfb, data);
        assert_ne!(encrypted_cfb, data);

        // Test AES-128-GCM
        let encrypted_gcm = encrypt_data(data, &key, &iv, VmessEncryption::Aes128Gcm).unwrap();
        let decrypted_gcm = decrypt_data(&encrypted_gcm, &key, &iv, VmessEncryption::Aes128Gcm).unwrap();
        assert_eq!(decrypted_gcm, data);
        assert_ne!(encrypted_gcm, data);

        // Test ChaCha20-Poly1305
        let encrypted_chacha = encrypt_data(data, &key, &iv, VmessEncryption::ChaCha20Poly1305).unwrap();
        let decrypted_chacha = decrypt_data(&encrypted_chacha, &key, &iv, VmessEncryption::ChaCha20Poly1305).unwrap();
        assert_eq!(decrypted_chacha, data);
        assert_ne!(encrypted_chacha, data);

        // Test None encryption
        let encrypted_none = encrypt_data(data, &key, &iv, VmessEncryption::None).unwrap();
        let decrypted_none = decrypt_data(&encrypted_none, &key, &iv, VmessEncryption::None).unwrap();
        assert_eq!(decrypted_none, data);
        assert_eq!(encrypted_none, data); // No encryption should return same data
    }
}

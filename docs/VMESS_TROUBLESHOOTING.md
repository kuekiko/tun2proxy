# VMess Troubleshooting Guide

## Common Issues and Solutions

### 1. Connection Issues

#### Problem: "Invalid VMess UUID" Error
```
Error: Invalid VMess UUID: invalid character 'x' in UUID
```

**Cause**: The UUID provided in the proxy URL is malformed.

**Solution**:
- Ensure the UUID is in the correct format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- Use a valid UUID generator or get the correct UUID from your VMess server
- Example valid UUID: `550e8400-e29b-41d4-a716-446655440000`

**Example**:
```bash
# Wrong
--proxy "vmess://invalid-uuid@example.com:10086"

# Correct
--proxy "vmess://550e8400-e29b-41d4-a716-446655440000@example.com:10086"
```

#### Problem: "VMess requires a UUID in the username field" Error

**Cause**: No UUID provided in the proxy URL.

**Solution**:
- Always include the UUID as the username part of the URL
- Format: `vmess://UUID@host:port`

#### Problem: Connection Timeout

**Symptoms**:
- Long delays before connection failure
- No response from server

**Troubleshooting Steps**:
1. **Check Server Availability**:
   ```bash
   telnet server_ip server_port
   ```

2. **Verify Network Connectivity**:
   ```bash
   ping server_ip
   ```

3. **Check Firewall Rules**:
   - Ensure outbound connections to the server port are allowed
   - Check if the server port is accessible

4. **Test with Different Encryption**:
   ```bash
   # Try with no encryption for testing
   --proxy "vmess://uuid@host:port?encryption=none"
   ```

### 2. Authentication Issues

#### Problem: "VMess response authentication failed" Error

**Cause**: Server rejected the authentication or UUID mismatch.

**Solutions**:
1. **Verify UUID**: Ensure the UUID matches the server configuration
2. **Check Time Synchronization**: VMess uses timestamps for replay protection
   ```bash
   # On Linux/macOS
   sudo ntpdate -s time.nist.gov
   
   # On Windows
   w32tm /resync
   ```
3. **Verify Server Configuration**: Ensure the server is configured to accept your UUID

#### Problem: Authentication Timeout

**Cause**: Server is not responding to authentication requests.

**Solutions**:
1. Check if the server is running VMess protocol
2. Verify the port number is correct
3. Ensure the server is not overloaded

### 3. Performance Issues

#### Problem: Slow Connection Speed

**Symptoms**:
- High latency
- Low throughput
- Frequent timeouts

**Optimization Steps**:
1. **Choose Optimal Encryption**:
   ```bash
   # Fastest (for testing)
   --proxy "vmess://uuid@host:port?encryption=none"
   
   # Good balance of speed and security
   --proxy "vmess://uuid@host:port?encryption=chacha20-poly1305"
   
   # Most secure but slower
   --proxy "vmess://uuid@host:port?encryption=aes-128-gcm"
   ```

2. **Check Network Path**:
   ```bash
   traceroute server_ip
   ```

3. **Monitor Resource Usage**:
   ```bash
   # Check CPU and memory usage
   top
   htop
   ```

#### Problem: High Memory Usage

**Symptoms**:
- Increasing memory consumption over time
- Out of memory errors

**Solutions**:
1. **Monitor Connection Count**: Limit concurrent connections
2. **Check for Memory Leaks**: Restart the application periodically
3. **Adjust Buffer Sizes**: Use smaller buffer sizes if memory is limited

### 4. Configuration Issues

#### Problem: "Unsupported protocol for VMess" Error

**Cause**: Trying to use VMess with unsupported protocols (ICMP, etc.).

**Solution**:
- VMess only supports TCP and UDP protocols
- Ensure your traffic is TCP or UDP based

#### Problem: Invalid Configuration Parameters

**Symptoms**:
- Configuration parsing errors
- Unexpected behavior

**Valid Configuration Examples**:
```bash
# Basic configuration
--proxy "vmess://uuid@host:port"

# With encryption
--proxy "vmess://uuid@host:port?encryption=aes-128-gcm"

# With all options
--proxy "vmess://uuid@host:port?encryption=chacha20-poly1305&alterId=0&security=high&test=false"
```

### 5. Debugging Steps

#### Enable Debug Logging

Set the log level to debug for more detailed information:
```bash
RUST_LOG=debug ./tun2proxy-bin --proxy "vmess://uuid@host:port"
```

#### Capture Network Traffic

Use network analysis tools to inspect traffic:
```bash
# Linux
sudo tcpdump -i any -w vmess_traffic.pcap host server_ip

# Windows (requires Wireshark)
# Use Wireshark to capture traffic on the network interface
```

#### Test with Simple Configuration

Start with the most basic configuration and add complexity:
```bash
# Step 1: Test basic connection
--proxy "vmess://uuid@host:port?encryption=none"

# Step 2: Add encryption
--proxy "vmess://uuid@host:port?encryption=aes-128-cfb"

# Step 3: Add advanced options
--proxy "vmess://uuid@host:port?encryption=aes-128-gcm&security=high"
```

### 6. Server-Side Issues

#### Problem: Server Not Responding

**Check Server Status**:
1. Verify the VMess server is running
2. Check server logs for errors
3. Ensure the server configuration includes your UUID
4. Verify the server is listening on the correct port

#### Problem: Server Configuration Mismatch

**Common Mismatches**:
- UUID not configured on server
- Different encryption methods
- Port number mismatch
- Protocol version incompatibility

**Solution**: Ensure client and server configurations match exactly.

### 7. Platform-Specific Issues

#### Windows

**Problem**: "Access Denied" when creating TUN interface
**Solution**: Run as Administrator

**Problem**: Windows Defender blocking connections
**Solution**: Add tun2proxy to Windows Defender exclusions

#### Linux

**Problem**: Permission denied for TUN interface
**Solution**: 
```bash
sudo setcap cap_net_admin+ep ./tun2proxy-bin
# or run with sudo
```

#### macOS

**Problem**: TUN interface creation fails
**Solution**: Install TUN/TAP drivers or use built-in utun interface

### 8. Performance Tuning

#### Optimal Settings for Different Use Cases

**Low Latency (Gaming)**:
```bash
--proxy "vmess://uuid@host:port?encryption=none"
```

**Balanced (General Use)**:
```bash
--proxy "vmess://uuid@host:port?encryption=chacha20-poly1305"
```

**High Security**:
```bash
--proxy "vmess://uuid@host:port?encryption=aes-128-gcm&security=high"
```

#### System Tuning

**Linux**:
```bash
# Increase network buffer sizes
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

**Windows**:
- Adjust TCP window scaling in registry
- Disable TCP chimney offload if experiencing issues

### 9. Monitoring and Diagnostics

#### Key Metrics to Monitor

1. **Connection Success Rate**: Percentage of successful connections
2. **Latency**: Round-trip time to server
3. **Throughput**: Data transfer rate
4. **Error Rate**: Frequency of connection errors
5. **Memory Usage**: RAM consumption over time

#### Diagnostic Commands

```bash
# Test basic connectivity
ping server_ip

# Test port accessibility
telnet server_ip server_port
nc -zv server_ip server_port

# Check DNS resolution
nslookup server_hostname
dig server_hostname

# Monitor network interface
netstat -i
ip link show
```

### 10. Getting Help

#### Information to Provide

When seeking help, include:
1. **Operating System**: Version and architecture
2. **tun2proxy Version**: Output of `--version`
3. **Command Line**: Exact command used (redact sensitive info)
4. **Error Messages**: Complete error output
5. **Network Environment**: Firewall, proxy, VPN status
6. **Server Information**: VMess server type and version (if known)

#### Log Collection

```bash
# Collect debug logs
RUST_LOG=debug ./tun2proxy-bin [options] 2>&1 | tee debug.log

# Collect system information
uname -a > system_info.txt
ip addr show >> system_info.txt
```

#### Community Resources

- GitHub Issues: Report bugs and feature requests
- Documentation: Check the latest documentation
- Examples: Review working configuration examples

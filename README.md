web / master


agent / node

./agent -a ip:port -i task1 -passwd


default tls










```rust
protocol
/*

# Step 1 —— 增加一个真正的 KDF（最关键！）
pass_key = Argon2id(pass, salt)

# Step 2 —— 用 HKDF 派生不同用途的密钥
enc_key, mac_key, portal_id = HKDF(pass_key, info=f"portal-{tunnel_id}", L=96)

# Step 3 —— 签名使用 mac_key（不再用 pass_key）
portal_sign = HMAC_SHA256(portal_id + salt + nonce, mac_key)

# Step 4 —— 加密使用 enc_key（不再用 pass_key）
portal_data = salt + nonce + AES-GCM(Serialize(data), enc_key)

# Step 5 —— 最终消息保持你的结构
portal_msg = portal_sign + portal_data
*/
```

# 背景


最近有一些[hersql](https://github.com)的用户希望能支持mysql的`caching_sha2_password`认证方式，`caching_sha2_password`与常用的`mysql_native_password`认证过程差异还是比较大的，因此抽空研究了一下`caching_sha2_password`身份认证过程，并为`hersql`支持了`caching_sha2_password`的能力



> hersql是我开源的一款通过http隧道来代理mysql的工具，可以通过http服务来穿透内网的mysql server，地址：[github.com/Orlion/hersql](https://github.com):[FlowerCloud机场节点订阅](https://dahelaoshi.com)


# mysql身份认证过程


![image.png](https://s2.loli.net/2025/01/08/aj65q2uoBmbzvig.png)


Client与Server建立TCP连接后，Server返回`Initial Handshake Packet`，这个包中会携带Server默认的认证方式，因为此时还不清楚登录用户是谁，所以是无法返回准确的认证方式的。



> mysql8\.0这个值默认值为`caching_sha2_password`，低版本为`mysql_native_password`


Client会先以Server返回的认证方式对密码进行加密，然后通过`Handshake Response Packet`发送给Server，这一轮交互完成后接下来会存在三种case:


1. 认证失败。比如密码错误。
2. 认证成功。成功建立了连接，接下来可以进行命令通信。
3. 返回AuthMoreData包，这时又分为两种情况：
	* 包第二个字节 \= 0x03，随后是一个正常的 OK 数据包，这是当用户的密码已在Server缓存中并且身份验证已成功时的情况，这种称之为`“fast” authentication`。
	* 包第二个字节 \= 0x04，这意味着需要更多数据才能完成身份验证，在使用`caching_sha2_password` 认证方式时，这意味着用户密码不在Server缓存中，Server要求Client发送用户的完整密码，这就是所谓的`“full” authentication`。这时Client需要用Server的公钥对密码进行加密然后再次发送给Server。
4. 返回`auth switch”`包。Server收到`Handshake Response Packet`后会查询登录用户的认证方式，如果首次认证使用的认证方式与用户指定的认证方式不同，需要进行切换，会在`auth switch`包中携带准确的认证方式。接下来Client要用Server返回的这个准确的认证方式重新发起一轮认证请求。


# mysql\_native\_password



> mysql\_native\_password 身份验证插件从 MySQL 8\.0\.34 开始已弃用，在 MySQL 8\.4 中默认禁用，并从 MySQL 9\.0\.0 开始删除。


用户密码存储在`mysql.user`的`authentication_string`字段中。在`mysql_native_password`认证方式下Server端存储的用户密码为原始密码经过两个sha1后的哈希值，没有经过加盐，因此相同的密码存储的值是相同的。


## 通讯过程简析


Server端会在`Initial Handshake Packet`返回一个随机数，Client收到之后首先与Server相同的对原始密码进行两次sha1，然后把Server返回的随机数加到摘要中，最终进行一个异或运算，得到最终的认证字符串：



```
// Hash password using 4.1+ method (SHA1)
func scramblePassword(scramble []byte, password string) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA1(password)
	crypt := sha1.New()
	crypt.Write([]byte(password))
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA1(scramble + SHA1(stage1Hash))
	// inner Hash
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)

	// outer Hash
	crypt.Reset()
	crypt.Write(scramble)
	crypt.Write(hash)
	scramble = crypt.Sum(nil)

	// token = scrambleHash XOR stage1Hash
	for i := range scramble {
		scramble[i] ^= stage1[i]
	}
	return scramble
}

```

Client通过`Handshake Response Packet`发送给Server，Server采用与Client相同的算法生成认证字符串，如果两端生成的一致则说明密码正确，认证通过。


# caching\_sha2\_password


这种认证方式下存储在`mysql.user`的`authentication_string`字段中值为：


![image.png](https://static001.geekbang.org/infoq/dc/dcf28fff9a311aa215b0457f954661c6.png)


即利用盐值进行5000轮SHA256哈希。


## 通讯过程简析


同样Server端会先返回一个随机数，Client生成认证字符串的算法为`XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))`。Server端收到`Handshake Response Packet`之后首先会检查`username/SHA256(SHA256(user_password))` 是否与缓存匹配，如果匹配则认证成功。如果没有匹配的缓存则则要求Client通过SSL连接或者RSA公钥对密码进行加密后再次发送给Server端，Server解密后获取到密码明文然后得到哈希值判断密码是否正确。



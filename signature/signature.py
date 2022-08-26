from curses.ascii import alt
from web3.auto import w3
from web3 import HTTPProvider
from eth_account.messages import encode_defunct
from ecdsa import SigningKey, SECP256k1
from Crypto.Hash import keccak

# Example
# Generate different signatures by modifying `deterministic_generate_k` in` /lib/python3.8/site-packages/eth_keys/backends/native/ecdsa.py
# For example insert k_1 = k_1 + b'22asdfasddf` between line 99 and 100
# The following is two signatures for a given message that trace to the same address
# paramaters 1
# message_hash = 0x1476abb745d423bf09273f1afd887d951181d25adc66c4834a70491911b7f750
#     signature = 0xad4f4a6aa17bf47a5c58b7c4c83dfda3c0cf70aa98588a7e93a7f84b85a9cf106322948667ebf21341c3ce1566eaf5221ae0c89afa2592b3eb4b911c9dc93dc61b
# parameters 2
# message_hash = 0x1476abb745d423bf09273f1afd887d951181d25adc66c4834a70491911b7f750
#    signature = 0x6286754bdae7c897caf3d9bb45ecb72d50a2e1723ec40505be73b07cafb3dbd73bc2c7f77e755c13977ff59fc404ee837ffdc75935427d718b8d0fdc58c5b4d41b
# Both outputs the address corresponding to the private key

provider = w3.HTTPProvider('http://localhost:8545')
private_key = b"\xb2\\}\xb3\x1f\xee\xd9\x12''\xbf\t9\xdcv\x9a\x96VK-\xe4\xc4rm\x03[6\xec\xf1\xe5\xb3d"
account = w3.eth.account.from_key(private_key)

print("account address " + account._address)

hex_message = '0x49e299a55346'

message = encode_defunct(hexstr=hex_message)
print("message ", message)
signed_message = w3.eth.account.sign_message(message, private_key=private_key)

#alt_signature = SigningKey.from_string(string=private_key,curve=SECP256k1).sign_deterministic(bytes(msg, 'utf-8'), extra_entropy=b"")
#print(alt_signature )
#alt_signature = SigningKey.from_string(string=private_key,curve=SECP256k1).sign_deterministic(bytes(msg, 'utf-8'), extra_entropy=b"")
#print(alt_signature )

print("signed message ", signed_message)

recovered_address = w3.eth.account.recover_message(message, signature=signed_message.signature)

print(recovered_address)


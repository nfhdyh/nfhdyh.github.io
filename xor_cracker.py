#!/usr/bin/env python3
import base64

def hamming_distance(b1, b2):
    return sum(bin(b).count('1') for b in bytes(a ^ b for a, b in zip(b1, b2)))

def guess_keysize(data, max_ks=40):
    best = []
    for ks in range(2, max_ks + 1):
        chunks = [data[i*ks:(i+1)*ks] for i in range(min(4, len(data)//ks))]
        if len(chunks) < 2:
            continue
        total_dist = 0
        pairs = 0
        for i in range(len(chunks)):
            for j in range(i+1, len(chunks)):
                if len(chunks[i]) == len(chunks[j]) == ks:
                    total_dist += hamming_distance(chunks[i], chunks[j])
                    pairs += 1
        if pairs == 0:
            continue
        avg_dist = total_dist / pairs
        normalized = avg_dist / ks
        best.append((normalized, ks))
    best.sort()
    return [ks for _, ks in best[:5]]

def score_english(text):
    # 简化的英文评分
    score = 0
    for byte in text:
        ch = chr(byte)
        if ch.isalpha():
            score += 1
        elif ch == ' ':
            score += 2
        elif 32 <= byte <= 126:
            score += 0.5
        else:
            score -= 10
    return score

def break_single_byte_xor(data):
    best_score = -1
    best_key = 0
    best_result = b''
    for key in range(256):
        decrypted = bytes([b ^ key for b in data])
        score = score_english(decrypted)
        if score > best_score:
            best_score = score
            best_key = key
            best_result = decrypted
    return best_key, best_result

def break_repeating_key_xor(ciphertext, keysize):
    key = []
    for i in range(keysize):
        block = ciphertext[i::keysize]
        k, _ = break_single_byte_xor(block)
        key.append(k)
    return bytes(key)

def decrypt_with_key(ciphertext, key):
    return bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])

def main():
    print("=" * 50)
    print("破解重复密钥 XOR")
    print("=" * 50)
    
    # 读取密文
    with open('6.txt', 'r') as f:
        ciphertext_b64 = f.read().replace('\n', '')
    
    ciphertext = base64.b64decode(ciphertext_b64)
    print(f"密文长度: {len(ciphertext)} 字节")
    
    # 猜测密钥长度
    print("猜测密钥长度...")
    candidates = guess_keysize(ciphertext)
    print(f"候选密钥长度: {candidates}")
    
    # 尝试破解
    best_plaintext = b''
    best_score = -1
    best_key = b''
    
    for ks in candidates[:3]:
        print(f"尝试密钥长度 {ks}...")
        key = break_repeating_key_xor(ciphertext, ks)
        plaintext = decrypt_with_key(ciphertext, key)
        score = score_english(plaintext)
        print(f"  密钥: {key[:20].hex()}...")
        print(f"  评分: {score}")
        
        if score > best_score:
            best_score = score
            best_plaintext = plaintext
            best_key = key
    
    print("\n" + "=" * 50)
    print("破解成功!")
    print("=" * 50)
    print(f"密钥: {best_key[:30].decode('ascii', errors='replace')}...")
    print(f"\n明文预览:")
    print("-" * 50)
    print(best_plaintext[:500].decode('ascii', errors='replace'))
    print("-" * 50)
    
    # 保存结果
    with open('decrypted.txt', 'w', encoding='utf-8') as f:
        f.write(best_plaintext.decode('ascii', errors='replace'))
    print("\n完整结果已保存到: decrypted.txt")

if __name__ == "__main__":
    main()
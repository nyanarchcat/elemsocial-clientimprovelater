/**
 * преобразует ArrayBuffer в формат PEM
 * @param {ArrayBuffer} buffer - буфер данных для преобразования
 * @param {string} type - тип сертификата ("PUBLIC KEY", "PRIVATE KEY" и т.д и т.п.)
 * @returns {string} строка в формате PEM
 */
function arrayBufferToPem(buffer, type) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunkSize = 1024;
    
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.slice(i, i + chunkSize);
        binary += String.fromCharCode.apply(null, chunk);
    }
    
    const base64 = btoa(binary);
    let pem = `-----BEGIN ${type}-----\n`;
    const lines = base64.match(/.{1,64}/g);
    if (lines) {
        pem += lines.join('\n');
    } else {
        pem += base64;
    }
    pem += `\n-----END ${type}-----\n`;
    return pem;
}

/**
 * импортирует публичный ключ из формата PEM
 * @param {string} pk - публичный ключ в формате PEM
 * @returns {ArrayBuffer} буфер с данными ключа
 * @throws {Error} если формат ключа неверый
 */
function importPublicKey(pk) {
    if (!pk || typeof pk !== 'string') {
        throw new Error('Публичный ключ должен быть строкой PEM');
    }
    
    const base64String = pk
        .replace(/-----BEGIN PUBLIC KEY-----/, '')
        .replace(/-----END PUBLIC KEY-----/, '')
        .replace(/\s/g, '');
    
    try {
        const publicKeyBytes = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
        return publicKeyBytes.buffer;
    } catch (error) {
        throw new Error(`Ошибка импорта публичного ключа: ${error.message}`);
    }
}

/**
 * ипортирует приватный ключ из формата PEM
 * @param {string} pk - приватный ключ в формате PEM
 * @returns {ArrayBuffer} буфер с данными ключа
 * @throws {Error} если формат ключа неверный---везде только разные ошибки писать не буду комм
 */
function importPrivateKey(pk) {
    if (!pk || typeof pk !== 'string') {
        throw new Error('Приватный ключ должен быть строкой PEM');
    }
    
    const base64String = pk
        .replace(/-----BEGIN PRIVATE KEY-----/, '')
        .replace(/-----END PRIVATE KEY-----/, '')
        .replace(/\s/g, '');
    
    try {
        const privateKeyBytes = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
        return privateKeyBytes.buffer;
    } catch (error) {
        throw new Error(`Ошибка импорта приватного ключа: ${error.message}`);
    }
}

/**
 * шифрует данные с помощью RSA
 * @param {string} data - даные для шифрования
 * @param {string} pk - публичный ключ в формате PEM
 * @returns {Promise<Uint8Array>} зашифрованные данные
 */
async function rsaEncrypt(data, pk) {
    if (!data) {
        throw new Error('Данные для шифрования не предоставлены');
    }
    
    try {
        const publicKeyBuffer = importPublicKey(pk);
        const dataBuffer = new TextEncoder().encode(data);
        const publicKeyE = await crypto.subtle.importKey(
            'spki',
            publicKeyBuffer,
            { name: 'RSA-OAEP', hash: { name: 'SHA-256' } },
            true,
            ['encrypt']
        );
        const encryptedDataBuffer = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKeyE,
            dataBuffer
        );
        return new Uint8Array(encryptedDataBuffer);
    } catch (error) {
        throw new Error('Ошибка шифрования данных: ' + error.message);
    }
}

/**
 * расшифроввает данные с помощью RSA
 * @param {Uint8Array} data - зашифрованные данные
 * @param {ArrayBuffer} privateKey - приватный ключ в формате ArrayBuffer
 * @returns {Promise<string>} расшифрованные данные в виде строки
 */
async function rsaDecrypt(data, privateKey) {
    if (!data || !privateKey) {
        throw new Error('Не предоставлены данные или приватный ключ');
    }
    
    try {
        const privateKeyE = await crypto.subtle.importKey(
            'pkcs8',
            privateKey,
            { name: 'RSA-OAEP', hash: { name: 'SHA-256' } },
            true,
            ['decrypt']
        );
        const decryptedDataBuffer = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKeyE,
            data
        );
        return new TextDecoder().decode(decryptedDataBuffer);
    } catch (error) {
        throw new Error('Ошибка расшифровки данных: ' + error.message);
    }
}


/**
 * создает случайный AES-клюЧ
 * @param {number} [length=32]длина  ключа в байтах
 * @returns {string} ключ в фрпмате Base64
 */
function generateAESKey(length = 32) {
    if (![16, 24, 32].includes(length)) {
        throw new Error('Длина ключа должна быть 16, 24 или 32 байта');
    }
    
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return arrayBufferToBase64(bytes.buffer);
}

/**
 * Создает AES-ключ из строки используя SHA-256
 * @param {string} word - строка для создания ключа
 * @returns {Promise<string>} ключ в формате Base64
 */
async function aesCreateKeyFromWord(word) {
    if (!word || typeof word !== 'string') {
        throw new Error('Требуется непустая строка для создания ключа');
    }
    
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(word);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return arrayBufferToBase64(hashBuffer);
    } catch (error) {
        throw new Error(`Ошибка создания ключа: ${error.message}`);
    }
}

/**
 * Преобразут Base64 в ArrayBuffer
 * @param {string} base64 - строка в формате Base64
 * @returns {ArrayBuffer} буфер с данными
 */
function base64ToArrayBuffer(base64) {
    if (!base64 || typeof base64 !== 'string') {
        throw new Error('Требуется строка в формате Base64');
    }
    
    try {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; ++i) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    } catch (error) {
        throw new Error(`Ошибка декодирования Base64: ${error.message}`);
    }
}

/**
 * шифрует данные с помощью AES-CBC
 * @param {string} data - данные для шифрования
 * @param {string} keyBase64 - кключ в формате Base64
 * @returns {Promise<{ encrypted: Uint8Array, iv: Uint8Array }>} Объект с зашифрованными данными и IV
 */
async function aesEncrypt(data, keyBase64) {
    if (!data) {
        throw new Error('Данные для шифрования не предоставлены');
    }
    
    if (!keyBase64) {
        throw new Error('Ключ шифрования не предоставлен');
    }
    
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encodedData = new TextEncoder().encode(data);

    try {
        const importedKey = await crypto.subtle.importKey(
            'raw',
            base64ToArrayBuffer(keyBase64),
            { name: 'AES-CBC' },
            false,
            ['encrypt']
        );
        
        const encryptedBuffer = await crypto.subtle.encrypt(
            { name: 'AES-CBC', iv: iv },
            importedKey,
            encodedData
        );

        const result = new Uint8Array(iv.byteLength + encryptedBuffer.byteLength);
        result.set(iv);
        result.set(new Uint8Array(encryptedBuffer), iv.byteLength);
        
        return {
            encrypted: result,
            iv: iv 
        };
    } catch (error) {
        throw new Error(`Ошибка при шифровании: ${error.message}`);
    }
}

/**
 * Расшифровывает данные
 * @param {Uint8Array} data - Зашифрованные данные (включая IV в первых 16 байтах)
 * @param {string} keyBase64 - Ключ в формате Base64
 * @returns {Promise<string>} Расшифрованные данные в виде строки
 */
async function aesDecrypt(data, keyBase64) {
    if (!data || !(data instanceof Uint8Array)) {
        throw new Error('Неверный формат зашифрованных данных');
    }
    
    if (data.length <= 16) {
        throw new Error('Данные слишком короткие, должны включать IV (16 байт)');
    }
    
    try {
        const iv = data.slice(0, 16);
        const encrypted = data.slice(16);

        const importedKey = await crypto.subtle.importKey(
            'raw',
            base64ToArrayBuffer(keyBase64),
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );
        
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            importedKey,
            encrypted
        );
        
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
        throw new Error(`Ошибка при расшифровке: ${error.message}`);
    }
}

/**
 * Расшифровывает данные с помощью AES-CBC, используя ключ в виде Uint8Array
 * @param {Uint8Array} key - Ключ в виде Uint8Array
 * @returns {Promise<string>} Расшифрованные данные в виде строки
 снизу переименввана функция aesDecryptUnit8 в aesDecryptWithRawKey для лучшей читаемости.
 */
async function aesDecryptWithRawKey(data, key) {
    if (!data || !(data instanceof Uint8Array)) {
        throw new Error('Неверный формат зашифрованных данных');
    }
    
    if (!key || !(key instanceof Uint8Array)) {
        throw new Error('Ключ должен быть в формате Uint8Array');
    }
    
    if (data.length <= 16) {
        throw new Error('Данные слишком короткие, должны включать IV (16 байт)');
    }
    
    try {
        const iv = data.slice(0, 16);
        const encrypted = data.slice(16);

        const importedKey = await crypto.subtle.importKey(
            'raw',
            key.buffer,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );
        
        const decryptedBuffer = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            importedKey,
            encrypted
        );
        
        return new TextDecoder().decode(decryptedBuffer);
    } catch (error) {
        throw new Error(`Ошибка при расшифровке: ${error.message}`);
    }
}

/**
 * Расшифровывает файл с помощью AES-CBC
 * @param {ArrayBuffer} file - Зашифрованный файл
 * @param {string} keyBase64Ключ в формате Base64
 * @param {string} ivBase64 - IV в формате Base64
 * @returns {Promise<Uint8Array>} Расшифрованные данные
 */
async function aesDecryptFile(file, keyBase64, ivBase64) {
    if (!file) {
        throw new Error('Файл не предоставлен');
    }
    
    if (!keyBase64 || !ivBase64) {
        throw new Error('Ключ или IV не предоставлены');
    }
    
    try {
        const key = base64ToArrayBuffer(keyBase64);
        const iv = base64ToArrayBuffer(ivBase64);

        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            key,
            { name: 'AES-CBC' },
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: iv },
            cryptoKey,
            file
        );
        
        return new Uint8Array(decrypted);
    } catch (error) {
        throw new Error(`Ошибка расшифровки файла: ${error.message}`);
    }
}

/**
 * Преобразует Blob в Uint8Array
 * @param {Blob} blob - Blob для преобразования
 * @returns {Promise<Uint8Array>} Данные в виде Uint8Array
 */
async function blobToUint8Array(blob) {
    if (!blob || !(blob instanceof Blob)) {
        throw new Error('Требуется объект Blob');
    }
    
    try {
        const arrayBuffer = await blob.arrayBuffer();
        return new Uint8Array(arrayBuffer);
    } catch (error) {
        throw new Error(`Ошибка преобразования Blob: ${error.message}`);
    }
}

/**
 * Преобразует ArrayBuffer в Base64
 * @param {ArrayBuffer} buffer - Буфер для преобразовани
 * @returns {string} Строка в формате Base64
 */
function arrayBufferToBase64(buffer) {
    if (!buffer || !(buffer instanceof ArrayBuffer) && !(buffer.buffer instanceof ArrayBuffer)) {
        throw new Error('Требуется ArrayBuffer или TypedArray');
    }
    
    try {
        const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
        
        let binary = '';
        const chunkSize = 1024;
        
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.slice(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        
        return btoa(binary);
    } catch (error) {
        throw new Error(`Ошибка преобразоания в Base64: ${error.message}`);
    }
}

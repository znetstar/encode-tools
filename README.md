# Etomon Encode Tools

[![NPM](https://nodei.co/npm/@etomon/encode-tools.png)](https://nodei.co/npm/@etomon/encode-tools/)

[![Build Status](https://travis-ci.com/EtomonUSA/encode-tools.svg?branch=master)](https://travis-ci.com/EtomonUSA/encode-tools)

This package aggregates different libraries for encoding, serializing, compressing, generating ids and hashing things, exposing a common interface. 

*Many* other packages serve the same purpose, but our objective is to ensure a consistent experience in both node.js and the browser and standardize the api so functions work the same way across different underlying libraries.

Etomon Encode Tools also has a command line wrapper [`encode-cli`](https://github.com/znetstar/encode-cli).

## Examples
Encoding a Buffer as base64url

```
  let enc = new EncodeTools();
  let buf = Buffer.from('hello world', 'utf8');
  let newBuf = enc.encodeBuffer(buf, BinaryEncoding.base64url);
  console.log(newBuf.toString('utf8'));
```

Hashing an object wth xxhash
```
let enc = new EncodeTools();
let obj = { foo: 'bar' };
let newBuf = await enc.hashObject(obj, HashAlgorithm.xxhash64);
console.log(newBuf.toString('utf8'));
```

Serializing an object wth msgpack
```
let enc = new EncodeTools();
let obj = { foo: 'bar' };
let newBuf = await enc.serializeObject(obj, SerializationFormat.msgpack);
console.log(newBuf.toString('base64'));
```

Generating a base64-encoded UUID v4
```
let enc = new EncodeTools();
let newBuf = await enc.uniqueId(IDFormat.uuidv4);
console.log(newBuf.toString('base64'));
```


Compressing a buffer with lzma
```
let enc = new EncodeTools();
let newBuf = await enc.compress(Buffer.from('hi', 'utf8'), CompressionFormat.lzma);
console.log(newBuf.toString('base64'));
```

Resizing a png image
```
let enc = new EncodeTools();
let imageBuf = await (await new Promise((resolve, reject) => {
  new (Jimp)(500, 500, '#FFFFFF', (err: unknown, image: any) => {
    if (err) reject(err);
    else resolve(image);
  });
})).getBufferAsync('image/png');

let myResizedPng = await enc.resizeImage(imageBuf, { width: 250 }, ImageFormat.png);
```


## Algorithms

Below are a list of supported algorithms, their backing library, and their support in the browser.

### Binary Encoding

| Name        | Browser? | Underlying Package |
|-------------|----------|--------------------|
| nodeBuffer  | ✓        | buffer             |
| base64      | ✓        | (built-in)         |
| base64url   | ✓        | (built-in)         |
| hex         | ✓        | (built-in)         |
| base32      | ✓        | base32.js          |
| hashids     | ✓        | hashids            |
| arrayBuffer | ✓        | (built-in)         |

### Hashing
| Name     | Browser? | Underlying Package     |
|----------|----------|------------------------|
| crc32    | ✓        | hash-wasm              |
| xxhash3  |          | xxhash-addon           |
| xxhash64 | ✓        | xxhash-addon/hash-wasm |
| xxhash32 | ✓        | xxhash-addon/hash-wasm |
| md5      | ✓        | hash-wasm              |
| sha1     | ✓        | hash-wasm              |
| sha2     | ✓        | hash-wasm              |
| sha3     | ✓        | hash-wasm              |
| bcrypt   | ✓        | hash-wasm              |

### ID Generation

| Name         | Browser? | Underlying Package |
|--------------|----------|--------------------|
| uuidv4       | ✓        | uuid               |
| uuidv2       | ✓        | uuid               |
| uuidv4string | ✓        | uuid               |
| uuidv2string | ✓        | uuid               |
| objectId     | ✓        | bson-ext/bson      |
| nanoid       | ✓        | nanoid             |
| timestamp    | ✓        | (built in)         |

### Serialization

| Name    | Browser? | Underlying Package |
|---------|----------|--------------------|
| json    | ✓        | (built in)         |
| msgpack | ✓        | @msgpack/msgpack   |
| bson    | ✓        | bson-ext/bson      

### Compression

| Name    | Browser? | Underlying Package |
|---------|----------|--------------------|
| zstd    | ✓        | zstd-codec         |
| lzma    | ✓        | lzma/lzma-native   |

### Image Manipulation

| Name    | Browser? | Underlying Package |
|---------|----------|--------------------|
| png     | ✓        | jimp/sharp         |
| jpeg    | ✓        | jimp/sharp         |
| webp    |          | sharp              |
| avif    |          | sharp              |
| tiff    |          | sharp              |
| gif*    |          | sharp              |

## Requirements

Etomon Encode Tools runs in the browser and in node.js, with two exceptions. The `bson-ext`, `lzma-native` and `xxhash-addon` packages have native bindings, and so cannot run in the browser. For browser compatibility, the `EncodeTools` class uses the pure javascript `bson`, `lzma` and `hash-wsam` packages, respectively,  to provide equivalent support albeit at the cost of performance. Additionally, `hash-wsam` lacks support for xxhash3.

The `EncodeToolsNative` class will use the native packages `bson-ext`, `lzma-native` and `xxhash-addon` (and any future native packages). `bson-ext`, `lzma-native` and `xxhash-addon` are listed as peer dependencies, so they must be installed manually with `npm install --no-save bson-ext xxhash-addon lzma-native`.

The `gif` image format in `EncodeToolsNative` requires `libvips` compiled with ImageMagick support ([as described here](https://zb.gy/qPJH)). I haven't had time to re-build libvips on my machine, so there are no mocha tests for the `gif` format.

## Usage

Please see the documentation located at https://etomonusa.github.io/encode-tools/

## Tests

Tests are written in Mocha, to run use `npm test`.

## License

Etomon Encode Tools is licensed under the GNU LGPL-3.0, a copy of which can be found at [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).

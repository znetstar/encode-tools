import {Buffer} from 'buffer';

import EncodeTools, {
  BinaryEncoding,
  BinaryInputOutput,
  CompressionFormat,
  EncodingOptions as BaseEncodingOptions,
  HashAlgorithm,
  IDFormat,
  InvalidFormat,
  SerializationFormat
} from './EncodeTools';
import * as crypto from 'crypto';

export {
  BinaryEncoding,
  BinaryInputOutput,
  EncodingOptions as BaseEncodingOptions,
  HashAlgorithm,
  IDFormat,
  SerializationFormat,
  CompressionFormat
} from './EncodeTools';

interface EncodingOptionsNative {
    hashAlgorithm: HashAlgorithm
}
const lzma = require('lzma-native');

export type EncodingOptions = BaseEncodingOptions&EncodingOptionsNative;

export const DEFAULT_ENCODE_TOOLS_NATIVE_OPTIONS: EncodingOptions = {
  binaryEncoding: BinaryEncoding.base64,
  hashAlgorithm: HashAlgorithm.xxhash3,
  serializationFormat: SerializationFormat.json,
  uniqueIdFormat: IDFormat.uuidv1String,
  compressionFormat: CompressionFormat.lzma
};

/**
 * Contains tools for encoding/decoding data in different circumstances.
 *
 * Will only attempt to use the native compiled npm libraries, returning an error if they aren't available.
 * This class will not work in browsers.
 */
export class EncodeToolsNative extends EncodeTools {
    constructor(public options: EncodingOptions = DEFAULT_ENCODE_TOOLS_NATIVE_OPTIONS) {
        super(options);
    }

  /**
   * Returns an instance of LZMA Native
   */
  public static lzmaNative(): any {
    if (typeof(require) === 'undefined')
      return null;
    return require('lzma-native');
  }


  /**
   * Returns an instance of XXHash Addon
   */
  public static xxhashNative(): any {
        if (typeof(require) === 'undefined')
            return null;
        return require('xxhash-addon');
    }

    /**
     * Hashes using XXHash-3 (https://zb.gy/l4kN), a fast, non-cryptographic,
     * hashing function.
     *
     * Uses XXHash from npm:xxhash-addon
     * @param buffer
     * @param args
     */
    public static async xxhash3(buffer: BinaryInputOutput, ...args: any[]): Promise<Buffer> {
        const { XXHash3 } = EncodeToolsNative.xxhashNative();
        const xxhash3 = new XXHash3(...args);
        let hash = xxhash3.hash(EncodeToolsNative.ensureBuffer(buffer));
        return Buffer.from(hash);
    }

    /**
     * Hashes using XXHash-32 (https://zb.gy/l4kN), a fast, non-cryptographic,
     * hashing function.
     *
     * Uses XXHash from npm:xxhash-addon
     * @param buffer
     * @param args
     */
    public static async xxhash32(buffer: BinaryInputOutput, ...args: any[]): Promise<Buffer> {
        const { XXHash32 } = EncodeToolsNative.xxhashNative();
        const xxhash32 = new XXHash32(...args);
        return Buffer.from(xxhash32.hash(EncodeToolsNative.ensureBuffer(buffer)));
    }
    /**
     * Hashes using XXHash-64 (https://zb.gy/l4kN), a fast, non-cryptographic,
     * hashing function.
     *
     * Uses XXHash from npm:xxhash-addon
     * @param buffer
     * @param args
     */
    public static async xxhash64(buffer: BinaryInputOutput, ...args: any[]): Promise<Buffer> {
        const { XXHash64 } = EncodeToolsNative.xxhashNative();
        const xxhash64 = new XXHash64(...args);
        return Buffer.from(xxhash64.hash(EncodeToolsNative.ensureBuffer(buffer)));
    }

    protected static nativeHash(buffer: BinaryInputOutput, algo: string): Buffer {
        const hash = crypto.createHash(algo);
        hash.update(EncodeToolsNative.ensureBuffer(buffer));
        return hash.digest();
    }

    /**
     * Uses the very popular, but UNSAFE, SHA-1 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses SHA1 from node.js api
     * @param buffer
     * @param args
     */
    public static async sha1(buffer: BinaryInputOutput): Promise<Buffer> {
        return EncodeToolsNative.nativeHash(buffer, 'sha1');
    }
    /**
     * Uses the popular, but UNSAFE, 512bit SHA-2 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses 512bit SHA from node.js api
     * @param buffer
     * @param args
     */
    public static async sha2(buffer: BinaryInputOutput): Promise<Buffer> {
        return EncodeToolsNative.nativeHash(buffer, 'sha512');
    }

    /**
     * Uses the very popular, but VERY VERY UNSAFE, MD5 cryptographic algorithm.
     * Use SHA3 for new projects.
     *
     * Uses 512bit SHA from node.js api
     * @param buffer
     * @param args
     */
    public static async md5(buffer: BinaryInputOutput): Promise<Buffer> {
        return EncodeToolsNative.nativeHash(buffer, 'md5');
    }

  /**
   * Returns an EncodeTools instance with the default properties
   */
    public static get WithDefaults() {
        return new EncodeToolsNative();
    }

  /**
   * Compresses a buffer using LZMA
   * @param buf - Buffer
   * @param mode - Compression mode (1-9)
   */
  public static async compressLZMA(buf: Buffer, mode: number): Promise<Buffer> {
    let lzma = EncodeToolsNative.lzmaNative();
    return new Promise<Buffer>((resolve, reject) => {
      lzma.compress(buf, mode, (result: any, error: any) => {
        if (error) reject(error);
        else resolve(result);
      });
    });

  }

  /**
   * Decompresses a buffer using LZMA
   * @param buf - Buffer
   * @param mode - Compression mode (1-9)
   */
  public static async decompressLZMA(buf: Buffer): Promise<Buffer> {
    let lzma = EncodeToolsNative.lzmaNative();
    return new Promise<Buffer>((resolve, reject) => {
      lzma.decompress(buf, (result: any, error: any) => {
        if (error) reject(error);
        else resolve(result);
      });
    });
  }

  /**
   * Compresses arbitrary data using the provided format and any options
   * @param data - Data to compress
   * @param format - Format to use
   * @param args - Options
   */
  public async compress(data: BinaryInputOutput, format: CompressionFormat = CompressionFormat.lzma, ...args: any[]): Promise<Buffer> {
    if (format === CompressionFormat.lzma) {
      return EncodeToolsNative.compressLZMA(EncodeToolsNative.ensureBuffer(data), args[0]);
    }
    throw new InvalidFormat(format);
  }

  /**
   * Decompresses arbitrary data using the provided format and any options
   * @param data - Data to decompress
   * @param format - Format to use
   */
  public async decompress(data: BinaryInputOutput,  format: CompressionFormat = CompressionFormat.lzma, ...args: any[]): Promise<Buffer> {
    if (format === CompressionFormat.lzma) {
      return EncodeToolsNative.decompressLZMA(EncodeToolsNative.ensureBuffer(data));
    }
    throw new InvalidFormat(format);
  }


  /**
     * Hashes data using the provided algorithm, returning a node.js Buffer.
     *
     * @param buffer
     * @param algorithm
     */
    public async hash(buffer: BinaryInputOutput, algorithm: HashAlgorithm = this.options.hashAlgorithm, ...args: any[]): Promise<Buffer> {
        if (algorithm === HashAlgorithm.xxhash3) return EncodeToolsNative.xxhash3(buffer, ...args);
        else if (algorithm === HashAlgorithm.xxhash64) return EncodeToolsNative.xxhash64(buffer, ...args);
        else if (algorithm === HashAlgorithm.xxhash32) return EncodeToolsNative.xxhash32(buffer, ...args);
        else if (algorithm === HashAlgorithm.sha1) return EncodeToolsNative.sha1(buffer);
        else if (algorithm === HashAlgorithm.sha2) return EncodeToolsNative.sha2(buffer);
        else if (algorithm === HashAlgorithm.md5) return EncodeToolsNative.md5(buffer);
        return super.hash(buffer, algorithm);
    }
}

export default EncodeToolsNative;

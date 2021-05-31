import {Buffer} from 'buffer';
import EncodeTools, {
  BinaryEncoding,
  BinaryInputOutput,
  CompressionFormat, CropDims,
  EncodingOptions as BaseEncodingOptions,
  HashAlgorithm as HashAlgorithmBase,
  IDFormat, ImageMetadata,
  InvalidFormat,
  SerializationFormat
} from './EncodeTools';
import * as crypto from 'crypto';
import * as Jimp from "jimp";
export {
  BinaryEncoding,
  BinaryInputOutput,
  EncodingOptions as BaseEncodingOptions,
  InvalidFormat,
  IDFormat,
  SerializationFormat,
  CompressionFormat,
  EncodeToolsFormat,
  EncodeToolsFunction
} from './EncodeTools';


export enum HashAlgorithm {
  /**
   * XXHash3
   */
  xxhash3 = 'xxhash3',
  crc32 = 'crc32',
  /**
   * Super fast non-cryptographic hashing algorithm.
   */
  xxhash64 = 'xxhash64',
  /**
   * Super fast non-cryptographic hashing algorithm.
   */
  xxhash32 = 'xxhash32',
  /**
   * Super fast non-cryptographic hashing algorithm.
   */
  /**
   * Insecure hashing algorithm, included for backwards compatibility.
   */
  md5 = 'md5',
  /**
   * SHA2 hashing algorithm.
   */
  sha1 = 'sha1',
  /**
   * SHA512 hashing algorithm.
   */
  sha512 = 'sha512',
  /**
   * SHA2 hashing algorithm.
   * @deprecated Use SHA512
   */
  sha2 = 'sha2',
  /**
   * SHA3 hashing algorithm.
   */
  sha3 = 'sha3',
  /**
   * BCrypt hashing algorithm
   */
  bcrypt = 'bcrypt',

}


/**
 * Format for converting images
 */
export enum ImageFormat {
  /**
   * PNG Format
   */
  png = 'png',
  /**
   * JPEG Format
   */
  jpeg = 'jpeg',
  // bmp = 'bmp',
  /**
   * WEBP Format
   */
  webp = 'webp',
  /**
   * AVIF Format
   */
  avif = 'avif',
  /**
   * TIFF Format
   */
  tiff = 'tiff',
  /**
   * Need to fix the libvips/ImageMagick error (https://zb.gy/qPJH).
   * @deprecated
   */
  gif = 'gif'
  /**
   * Export to svg does not work
   * @deprecated
   */
  // svg = 'svg',
}

export interface EncodingOptions {
  uniqueIdFormat?: IDFormat;
  serializationFormat?: SerializationFormat;
  hashAlgorithm?: HashAlgorithm;
  binaryEncoding?: BinaryEncoding;
  compressionFormat?: CompressionFormat;
  compressionLevel?: number;
  imageFormat?: ImageFormat;
}
const lzma = require('lzma-native');

export const DEFAULT_ENCODE_TOOLS_NATIVE_OPTIONS: EncodingOptions = {
  binaryEncoding: BinaryEncoding.base64,
  hashAlgorithm: HashAlgorithm.xxhash64,
  serializationFormat: SerializationFormat.json,
  uniqueIdFormat: IDFormat.uuidv1String,
  compressionFormat: CompressionFormat.lzma,
  imageFormat: ImageFormat.png
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

  // /**
  //  * Returns an instance of node-zstd
  //  */
  // public static async zstdNative(): Promise<any> {
  //   if (typeof(require) === 'undefined')
  //     return null;
  //   // @ts-ignore
  //   return require('@etomon/node-zstd');
  // }

  /**
   * Returns an instance of the `bson` node module, using the native `bson-ext` if available.
   *
   */
  protected static get bson(): any {
    let bson = EncodeTools.safeLoadModule('bson-ext');
    if (!bson)
      bson = require('bson');
    return bson;
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
     * Returns an instance of Sharp
     */
    public static sharpNative(): any {
      if (typeof(require) === 'undefined')
        return null;
      return require('sharp');
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
     * @deprecated Use sha512
     */
    public static async sha2(buffer: BinaryInputOutput): Promise<Buffer> {
        return EncodeToolsNative.sha512(buffer);
    }

  /**
   * Uses the popular, but UNSAFE, 512bit SHA- cryptographic algorithm.
   * Use SHA3 for new projects.
   *
   * Uses 512bit SHA from node.js api
   * @param buffer
   * @param args
   */
  public static async sha512(buffer: BinaryInputOutput): Promise<Buffer> {
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
   * @param level - Compression level (1-9)
   */
  public static async compressLZMA(buf: Buffer, level: number): Promise<Buffer> {
    let lzma = EncodeToolsNative.lzmaNative();
    return lzma.compress(buf, level);
  }

  /**
   * Decompresses a buffer using LZMA
   * @param buf - Buffer
   * @param level - Compression level (1-9)
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

  // /**
  //  * Compresses a buffer using ZStd
  //  * @param buf - Buffer
  //  * @param level - Compression level (1-9)
  //  */
  // public static async compressZStd(buf: Buffer, level: number): Promise<Buffer> {
  //   return (await EncodeToolsNative.cppzstNative()).compress(buf, level);
  // }
  //
  // /**
  //  * Decompresses a buffer using ZStd
  //  * @param buf - Buffer
  //  * @param level - Compression level (1-9)
  //  */
  // public static async decompressZStd(buf: Buffer): Promise<Buffer> {
  //   return (await EncodeToolsNative.cppzstNative()).decompress(buf);
  // }

  /**
   * Compresses arbitrary data using the provided format and any options
   * @param data - Data to compress
   * @param format - Format to use
   * @param args - Options
   */
  public async compress(data: Buffer|ArrayBuffer, format?: CompressionFormat.lzma, level?: number, ...args: any[]): Promise<Buffer>;
  public async compress(data: Buffer|ArrayBuffer, format?: CompressionFormat.zstd, level?: number, ...args: any[]): Promise<Buffer>;
  public async compress(data: BinaryInputOutput, format?: CompressionFormat, level?: number, ...args: any[]): Promise<Buffer>;
  public async compress(data: BinaryInputOutput, format: CompressionFormat = CompressionFormat.lzma, level: number = this.options.compressionLevel, ...args: any[]): Promise<Buffer> {
    if (format === CompressionFormat.lzma) {
      return EncodeToolsNative.compressLZMA(EncodeToolsNative.ensureBuffer(data), level);
    }
    // else if (format === CompressionFormat.zstd) {
    //   return EncodeToolsNative.compressZStd(EncodeToolsNative.ensureBuffer(data), level);
    // }
    return super.compress(data, format, level);
  }

  /**
   * Decompresses arbitrary data using the provided format and any options
   * @param data - Data to decompress
   * @param format - Format to use
   */
  public async decompress(data: Buffer|ArrayBuffer, format: CompressionFormat.lzma, ...args: any[]): Promise<Buffer>;
  public async decompress(data: Buffer|ArrayBuffer, format: CompressionFormat.zstd, ...args: any[]): Promise<Buffer>;
  public async decompress(data: BinaryInputOutput, format: CompressionFormat, ...args: any[]): Promise<Buffer>;
  public async decompress(data: BinaryInputOutput,  format: CompressionFormat = CompressionFormat.lzma, ...args: any[]): Promise<Buffer> {
    if (format === CompressionFormat.lzma) {
      return EncodeToolsNative.decompressLZMA(EncodeToolsNative.ensureBuffer(data));
    }
    // else if (format === CompressionFormat.zstd) {
    //   return EncodeToolsNative.decompressZStd(EncodeToolsNative.ensureBuffer(data));
    // }
    return super.decompress(data, format);
  }

  /**
   * Crops an image and returns a Buffer containing the result in the provided format
   * @param data - Image
   * @param dims - Height/Width to resize to
   * @param format - Format to save result as
   */
  public async cropImage(buffer: Buffer|ArrayBuffer, dims: CropDims, format?: ImageFormat.png): Promise<Buffer>;
  public async cropImage(buffer: Buffer|ArrayBuffer, dims: CropDims, format?: ImageFormat.jpeg): Promise<Buffer>;
  public async cropImage(buffer: Buffer|ArrayBuffer, dims: CropDims, format?: ImageFormat.webp): Promise<Buffer>;
  public async cropImage(buffer: Buffer|ArrayBuffer, dims: CropDims, format?: ImageFormat.avif): Promise<Buffer>;
  public async cropImage(buffer: Buffer|ArrayBuffer, dims: CropDims, format?: ImageFormat.tiff): Promise<Buffer>;
  // public async cropImage(buffer: Buffer|ArrayBuffer|string, dims: CropDims, format?: ImageFormat.svg): Promise<Buffer>;
  public async cropImage(data: BinaryInputOutput, dims: CropDims, format?: ImageFormat): Promise<Buffer>;
  public async cropImage(data: BinaryInputOutput, dims: CropDims, format: ImageFormat = this.options.imageFormat): Promise<Buffer> {
    // if (format === ImageFormat.bmp)
    //   return super.resizeImage(data, dims, format);

    let sharp = EncodeToolsNative.sharpNative()(EncodeTools.ensureBuffer(data));

    return await sharp.extract(dims).toFormat(format.toString()).toBuffer();
  }


  /**
   * Resizes an image and returns a Buffer containing the result in the provided format
   * @param data - Image
   * @param dims - Height/Width to resize to
   * @param format - Format to save result as
   */
  public async resizeImage(buffer: Buffer|ArrayBuffer, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.png): Promise<Buffer>;
  public async resizeImage(buffer: Buffer|ArrayBuffer, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.jpeg): Promise<Buffer>;
  public async resizeImage(buffer: Buffer|ArrayBuffer, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.webp): Promise<Buffer>;
  public async resizeImage(buffer: Buffer|ArrayBuffer, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.avif): Promise<Buffer>;
  public async resizeImage(buffer: Buffer|ArrayBuffer, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.tiff): Promise<Buffer>;
  // public async resizeImage(buffer: Buffer|ArrayBuffer|string, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat.svg): Promise<Buffer>;
  public async resizeImage(data: BinaryInputOutput, dims: { height: number, width?: number }|{ height?: number, width: number }, format?: ImageFormat): Promise<Buffer>;
  public async resizeImage(data: BinaryInputOutput, dims: { height: number, width?: number }|{ height?: number, width: number }, format: ImageFormat = this.options.imageFormat): Promise<Buffer> {
    // if (format === ImageFormat.bmp)
    //   return super.resizeImage(data, dims, format);

    let sharp = EncodeToolsNative.sharpNative()(EncodeTools.ensureBuffer(data));

    return await sharp.resize(dims).toFormat(format.toString()).toBuffer();
  }

  /**
   * Saves an image in the provided format, performing no operations on the image
   * @param data - Image
   * @param format - Format to save result as
   */
  public async convertImage(buffer: Buffer|ArrayBuffer, format?: ImageFormat.png): Promise<Buffer>;
  public async convertImage(buffer: Buffer|ArrayBuffer, format?: ImageFormat.jpeg): Promise<Buffer>;
  public async convertImage(buffer: Buffer|ArrayBuffer, format?: ImageFormat.webp): Promise<Buffer>;
  public async convertImage(buffer: Buffer|ArrayBuffer, format?: ImageFormat.avif): Promise<Buffer>;
  public async convertImage(buffer: Buffer|ArrayBuffer, format?: ImageFormat.tiff): Promise<Buffer>;
  // public async convertImage(buffer: Buffer|ArrayBuffer|string, format?: ImageFormat.svg): Promise<Buffer>;
  public async convertImage(data: BinaryInputOutput, format?: ImageFormat): Promise<Buffer>;
  public async convertImage(data: BinaryInputOutput, format: ImageFormat = this.options.imageFormat): Promise<Buffer> {
    // if (format === ImageFormat.bmp)
    //   return super.resizeImage(data, format);

    let sharp = EncodeToolsNative.sharpNative()(EncodeTools.ensureBuffer(data));

    return await sharp.toFormat(format.toString()).toBuffer();
  }

  /**
   * Adjust brightness of image
   * @param data - Image
   * @param dims - Height/Width to resize to
   * @param format - Format to save result as
   */
  public async adjustImageBrightness(buffer: Buffer|ArrayBuffer, factor: number, format?: ImageFormat.png): Promise<Buffer>;
  public async adjustImageBrightness(buffer: Buffer|ArrayBuffer, factor: number, format?: ImageFormat.jpeg): Promise<Buffer>;
  public async adjustImageBrightness(buffer: Buffer|ArrayBuffer, factor: number, format?: ImageFormat.webp): Promise<Buffer>;
  public async adjustImageBrightness(buffer: Buffer|ArrayBuffer, factor: number, format?: ImageFormat.avif): Promise<Buffer>;
  public async adjustImageBrightness(buffer: Buffer|ArrayBuffer, factor: number, format?: ImageFormat.tiff): Promise<Buffer>;
  // public async adjustImageBrightness(buffer: Buffer|ArrayBuffer|string, factor: number, format?: ImageFormat.svg): Promise<Buffer>;
  public async adjustImageBrightness(data: BinaryInputOutput, factor: number, format?: ImageFormat): Promise<Buffer>;
  public async adjustImageBrightness(data: BinaryInputOutput, factor: number, format: ImageFormat = this.options.imageFormat): Promise<Buffer> {
    let sharp = EncodeToolsNative.sharpNative()(EncodeTools.ensureBuffer(data));

    return await sharp.modulate({ brightness: 1+factor }).toFormat(format.toString()).toBuffer();
  }

  /**
   * Gets metadata of the image provided as a buffer
   * @param data - Image
   */
  public static async getImageMetadata(buffer: Buffer|ArrayBuffer): Promise<ImageMetadata>;
  public static async getImageMetadata(buffer: Buffer|ArrayBuffer): Promise<ImageMetadata>;
  public static async getImageMetadata(buffer: string): Promise<ImageMetadata>;
  public static async getImageMetadata(data: BinaryInputOutput): Promise<ImageMetadata>;
  public static async getImageMetadata(data: BinaryInputOutput): Promise<ImageMetadata> {
    let sharp = EncodeToolsNative.sharpNative()(EncodeTools.ensureBuffer(data));

    let meta = await sharp.metadata();
    return {
      format: meta.format as ImageFormat,
      height: meta.height,
      width: meta.width
    }
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
      else if (algorithm === HashAlgorithm.sha512) return EncodeToolsNative.sha512(buffer);
      else if (algorithm === HashAlgorithm.md5) return EncodeToolsNative.md5(buffer);
      return super.hash(buffer, algorithm);
    }
}

export default EncodeToolsNative;

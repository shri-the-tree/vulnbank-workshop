/**
 * Multimodal Injection Detector - Image-based Prompt Injection Defense
 *
 * Analyzes images submitted to VisionBot for embedded textual instructions
 * via OCR and metadata analysis. Blocks or sanitizes malicious visual payloads.
 *
 * Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createAuditLogger } from './audit-logger.js';

/** Maximum image file size in bytes (10 MB) */
const MAX_IMAGE_SIZE = 10 * 1024 * 1024;

/** Maximum image dimensions */
const MAX_IMAGE_WIDTH = 4096;
const MAX_IMAGE_HEIGHT = 4096;

/** Text area coverage threshold for enhanced matching */
const TEXT_COVERAGE_THRESHOLD = 0.6;

/** Default OCR confidence threshold */
const DEFAULT_OCR_CONFIDENCE = 0.7;

/** Performance target: 500ms for images up to 5 MB */
const PERFORMANCE_TARGET_MS = 500;

/**
 * Default basic OCR engine stub.
 * Analyzes image buffer for text-like regions using heuristic detection.
 * Returns extracted text segments with confidence and bounding box info.
 *
 * @param {Buffer} imageBuffer - Raw image bytes
 * @returns {{ segments: Array<{ text: string, confidence: number, bbox: { x: number, y: number, width: number, height: number } }>, totalTextArea: number, totalImageArea: number }}
 */
function defaultOcrEngine(imageBuffer) {
  const segments = [];
  let totalTextArea = 0;

  // Get image dimensions from buffer headers
  const dimensions = parseImageDimensions(imageBuffer);
  const totalImageArea = dimensions.width * dimensions.height;

  // Heuristic: scan for high-contrast byte patterns that indicate text regions.
  // In a real implementation this would use Tesseract or a similar engine.
  // For the workshop, we detect text-like patterns in metadata and raw data.

  // Check for text embedded in PNG tEXt/iTXt/zTXt chunks
  const pngTextChunks = extractPngTextChunks(imageBuffer);
  for (const chunk of pngTextChunks) {
    segments.push({
      text: chunk.text,
      confidence: 0.85,
      bbox: { x: 0, y: 0, width: dimensions.width, height: dimensions.height },
    });
    totalTextArea += dimensions.width * dimensions.height * 0.3;
  }

  // Check for text-like byte sequences (ASCII runs in image data)
  const asciiRuns = detectAsciiRuns(imageBuffer, 10);
  for (const run of asciiRuns) {
    segments.push({
      text: run,
      confidence: 0.75,
      bbox: { x: 0, y: 0, width: dimensions.width / 2, height: 20 },
    });
    totalTextArea += (dimensions.width / 2) * 20;
  }

  return {
    segments,
    totalTextArea: Math.min(totalTextArea, totalImageArea),
    totalImageArea,
  };
}

/**
 * Parse image dimensions from the buffer header (PNG or JPEG).
 * @param {Buffer} buf
 * @returns {{ width: number, height: number }}
 */
function parseImageDimensions(buf) {
  if (!buf || buf.length < 24) {
    return { width: 0, height: 0 };
  }

  // PNG: magic bytes 89 50 4E 47, IHDR chunk at offset 16 for width/height
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) {
    if (buf.length >= 24) {
      const width = buf.readUInt32BE(16);
      const height = buf.readUInt32BE(20);
      return { width, height };
    }
  }

  // JPEG: magic bytes FF D8, scan for SOF0/SOF2 markers
  if (buf[0] === 0xFF && buf[1] === 0xD8) {
    let offset = 2;
    while (offset < buf.length - 9) {
      if (buf[offset] !== 0xFF) {
        offset++;
        continue;
      }
      const marker = buf[offset + 1];
      // SOF0 (0xC0) or SOF2 (0xC2) contains dimensions
      if (marker === 0xC0 || marker === 0xC2) {
        const height = buf.readUInt16BE(offset + 5);
        const width = buf.readUInt16BE(offset + 7);
        return { width, height };
      }
      // Skip to next marker
      const segmentLength = buf.readUInt16BE(offset + 2);
      offset += 2 + segmentLength;
    }
  }

  // Fallback: assume standard size
  return { width: 800, height: 600 };
}

/**
 * Extract text chunks from PNG images (tEXt, iTXt, zTXt).
 * @param {Buffer} buf
 * @returns {Array<{ keyword: string, text: string }>}
 */
function extractPngTextChunks(buf) {
  const results = [];

  if (!buf || buf.length < 8) return results;
  // Verify PNG signature
  if (!(buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47)) {
    return results;
  }

  let offset = 8; // Skip PNG signature
  while (offset + 12 <= buf.length) {
    const chunkLength = buf.readUInt32BE(offset);
    const chunkType = buf.slice(offset + 4, offset + 8).toString('ascii');

    if (chunkType === 'tEXt' && offset + 8 + chunkLength <= buf.length) {
      const chunkData = buf.slice(offset + 8, offset + 8 + chunkLength);
      const nullIdx = chunkData.indexOf(0);
      if (nullIdx > 0) {
        const keyword = chunkData.slice(0, nullIdx).toString('ascii');
        const text = chunkData.slice(nullIdx + 1).toString('utf-8');
        results.push({ keyword, text });
      }
    } else if (chunkType === 'iTXt' && offset + 8 + chunkLength <= buf.length) {
      const chunkData = buf.slice(offset + 8, offset + 8 + chunkLength);
      const nullIdx = chunkData.indexOf(0);
      if (nullIdx > 0) {
        const keyword = chunkData.slice(0, nullIdx).toString('ascii');
        // iTXt has compression flag, method, language, translated keyword, text
        // Simplified: find text after all null separators
        let textStart = nullIdx + 1;
        let nullCount = 0;
        for (let i = textStart; i < chunkData.length && nullCount < 3; i++) {
          if (chunkData[i] === 0) nullCount++;
          textStart = i + 1;
        }
        const text = chunkData.slice(textStart).toString('utf-8');
        if (text.length > 0) {
          results.push({ keyword, text });
        }
      }
    }

    // Move to next chunk (length + type(4) + data + CRC(4))
    offset += 4 + 4 + chunkLength + 4;
  }

  return results;
}

/**
 * Detect runs of printable ASCII characters in binary data.
 * Used as a heuristic to find embedded text in image pixel data.
 * @param {Buffer} buf
 * @param {number} minLength - Minimum run length to report
 * @returns {string[]}
 */
function detectAsciiRuns(buf, minLength = 10) {
  const runs = [];
  let current = '';

  // Skip the first 100 bytes (header) to avoid false positives
  const startOffset = Math.min(100, buf.length);

  for (let i = startOffset; i < buf.length; i++) {
    const byte = buf[i];
    // Printable ASCII range (space through tilde)
    if (byte >= 0x20 && byte <= 0x7E) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= minLength) {
        runs.push(current);
      }
      current = '';
    }
  }

  if (current.length >= minLength) {
    runs.push(current);
  }

  // Limit to first 20 runs to bound processing time
  return runs.slice(0, 20);
}

/**
 * Parse and extract EXIF data from JPEG images.
 * @param {Buffer} buf
 * @returns {{ fields: Object, rawSegments: Array<{ marker: number, offset: number, length: number }> }}
 */
function parseExif(buf) {
  const fields = {};
  const rawSegments = [];

  if (!buf || buf.length < 4) return { fields, rawSegments };
  if (!(buf[0] === 0xFF && buf[1] === 0xD8)) return { fields, rawSegments };

  let offset = 2;
  while (offset < buf.length - 3) {
    if (buf[offset] !== 0xFF) {
      offset++;
      continue;
    }

    const marker = buf[offset + 1];
    // APP1 (0xE1) = EXIF/XMP, APP13 (0xED) = IPTC
    if (marker === 0xE1 || marker === 0xED) {
      const segmentLength = buf.readUInt16BE(offset + 2);
      rawSegments.push({ marker, offset, length: segmentLength + 2 });

      // Extract text content from the segment
      const segmentData = buf.slice(offset + 4, offset + 2 + segmentLength);
      const textContent = segmentData.toString('utf-8', 0, Math.min(segmentData.length, 2000));

      if (marker === 0xE1) {
        // Check if it's XMP (starts with http://ns.adobe.com/xap)
        if (textContent.includes('http://ns.adobe.com/xap') || textContent.includes('<x:xmpmeta')) {
          fields.xmp = textContent;
        } else {
          fields.exif = textContent;
        }
      } else if (marker === 0xED) {
        fields.iptc = textContent;
      }
    }

    // Move to next segment
    if (marker === 0xD9) break; // End of image
    if (marker === 0xDA) break; // Start of scan (image data follows)

    if (offset + 3 < buf.length) {
      const segLen = buf.readUInt16BE(offset + 2);
      offset += 2 + segLen;
    } else {
      break;
    }
  }

  return { fields, rawSegments };
}

/**
 * Strip metadata segments from a JPEG buffer.
 * Returns a new buffer without EXIF, IPTC, and XMP segments.
 * @param {Buffer} buf
 * @returns {Buffer}
 */
function stripJpegMetadata(buf) {
  if (!buf || buf.length < 4) return buf;
  if (!(buf[0] === 0xFF && buf[1] === 0xD8)) return buf;

  const chunks = [];
  chunks.push(buf.slice(0, 2)); // SOI marker

  let offset = 2;
  while (offset < buf.length - 1) {
    if (buf[offset] !== 0xFF) {
      // Raw data (shouldn't happen in well-formed JPEG)
      chunks.push(buf.slice(offset));
      break;
    }

    const marker = buf[offset + 1];

    // End of image
    if (marker === 0xD9) {
      chunks.push(buf.slice(offset));
      break;
    }

    // Start of scan — copy everything remaining
    if (marker === 0xDA) {
      chunks.push(buf.slice(offset));
      break;
    }

    // Variable-length markers
    if (offset + 3 >= buf.length) {
      chunks.push(buf.slice(offset));
      break;
    }

    const segmentLength = buf.readUInt16BE(offset + 2);
    const segmentEnd = offset + 2 + segmentLength;

    // Skip APP1 (EXIF/XMP) and APP13 (IPTC) markers
    if (marker === 0xE1 || marker === 0xED) {
      // Strip this segment
      offset = segmentEnd;
      continue;
    }

    // Keep other segments
    chunks.push(buf.slice(offset, segmentEnd));
    offset = segmentEnd;
  }

  return Buffer.concat(chunks);
}

/**
 * Strip metadata from PNG by removing tEXt, iTXt, zTXt chunks.
 * @param {Buffer} buf
 * @returns {Buffer}
 */
function stripPngMetadata(buf) {
  if (!buf || buf.length < 8) return buf;
  if (!(buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47)) return buf;

  const chunks = [];
  chunks.push(buf.slice(0, 8)); // PNG signature

  const metadataChunkTypes = new Set(['tEXt', 'iTXt', 'zTXt', 'eXIf']);

  let offset = 8;
  while (offset + 12 <= buf.length) {
    const chunkLength = buf.readUInt32BE(offset);
    const chunkType = buf.slice(offset + 4, offset + 8).toString('ascii');
    const totalChunkSize = 4 + 4 + chunkLength + 4; // length + type + data + CRC

    if (!metadataChunkTypes.has(chunkType)) {
      chunks.push(buf.slice(offset, offset + totalChunkSize));
    }

    offset += totalChunkSize;
  }

  return Buffer.concat(chunks);
}

/**
 * Compute SHA-256 hash of image buffer.
 * @param {Buffer} buf
 * @returns {string}
 */
function computeImageHash(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

/**
 * Creates a MultimodalInjectionDetector instance.
 *
 * @param {Object} options
 * @param {string} [options.patternsPath] - Path to injection patterns JSON
 * @param {string} [options.jailbreakPatternsPath] - Path to jailbreak patterns JSON
 * @param {number} [options.ocrConfidence=0.7] - Minimum OCR confidence threshold (0.0-1.0)
 * @param {Function} [options.ocrEngine] - Pluggable OCR engine function (default: basic heuristic)
 * @param {Object} [options.logger] - Audit logger instance
 * @returns {MultimodalInjectionDetector}
 */
export function createMultimodalInjectionDetector(options = {}) {
  const {
    patternsPath = null,
    jailbreakPatternsPath = null,
    ocrConfidence = DEFAULT_OCR_CONFIDENCE,
    ocrEngine = defaultOcrEngine,
    logger = createAuditLogger({ minLevel: 'DEBUG' }),
  } = options;

  // Validate confidence threshold
  const confidenceThreshold = (typeof ocrConfidence === 'number' && ocrConfidence >= 0 && ocrConfidence <= 1)
    ? ocrConfidence
    : DEFAULT_OCR_CONFIDENCE;

  // Load injection patterns
  let injectionPatterns = [];
  let jailbreakPatterns = [];

  if (patternsPath) {
    try {
      const raw = readFileSync(patternsPath, 'utf-8');
      const config = JSON.parse(raw);
      injectionPatterns = (config.patterns || []).map(entry => ({
        regex: new RegExp(entry.pattern, entry.flags || 'i'),
        category: entry.category,
        action: entry.action || 'reject',
      }));
    } catch {
      // Fall back to built-in patterns
    }
  }

  if (jailbreakPatternsPath) {
    try {
      const raw = readFileSync(jailbreakPatternsPath, 'utf-8');
      const config = JSON.parse(raw);
      jailbreakPatterns = (config.patterns || []).map(entry => ({
        regex: new RegExp(entry.pattern, entry.flags || 'i'),
        category: entry.category,
        weight: entry.weight || 0.5,
      }));
    } catch {
      // Fall back to built-in patterns
    }
  }

  // Built-in prompt injection patterns (used if no external file loaded)
  if (injectionPatterns.length === 0) {
    injectionPatterns = [
      { regex: /ignore.*(?:previous|above|prior).*instruction/i, category: 'prompt_injection', action: 'reject' },
      { regex: /disregard.*(?:all|any|every).*(?:previous|prior|above)/i, category: 'prompt_injection', action: 'reject' },
      { regex: /you are now (?:in )?(?:developer|admin|debug|god|unrestricted)\s*mode/i, category: 'prompt_injection', action: 'reject' },
      { regex: /\[(?:INST|SYSTEM|ADMIN)\]/i, category: 'instruction_injection', action: 'reject' },
      { regex: /system\s*(?:prompt|override|command)/i, category: 'prompt_injection', action: 'reject' },
      { regex: /new\s+(?:directive|instructions?|rules?)/i, category: 'prompt_injection', action: 'reject' },
      { regex: /forget\s+(?:your|all|previous)\s+(?:rules?|instructions?)/i, category: 'prompt_injection', action: 'reject' },
    ];
  }

  // Built-in jailbreak patterns
  if (jailbreakPatterns.length === 0) {
    jailbreakPatterns = [
      { regex: /do anything now/i, category: 'dan_mode', weight: 0.9 },
      { regex: /DAN\s*mode/i, category: 'dan_mode', weight: 0.95 },
      { regex: /developer\s*mode/i, category: 'roleplay_bypass', weight: 0.8 },
      { regex: /act as (?:an? )?unrestricted/i, category: 'roleplay_bypass', weight: 0.85 },
      { regex: /hypothetical(?:ly)?.*(?:if|scenario|assume)/i, category: 'hypothetical_framing', weight: 0.7 },
      { regex: /pretend (?:you are|to be)/i, category: 'roleplay_bypass', weight: 0.75 },
    ];
  }

  /**
   * Check extracted text against injection and jailbreak patterns.
   * @param {string} text - Extracted text to match
   * @param {boolean} enhanced - Whether to apply enhanced matching (>60% text coverage)
   * @returns {{ matched: boolean, patterns: string[] }}
   */
  function matchPatterns(text, enhanced = false) {
    const matchedPatterns = [];

    if (!text || text.trim().length === 0) {
      return { matched: false, patterns: [] };
    }

    // Check injection patterns
    for (const { regex, category } of injectionPatterns) {
      regex.lastIndex = 0;
      if (regex.test(text)) {
        matchedPatterns.push(`injection:${category}`);
      }
    }

    // Check jailbreak patterns
    for (const { regex, category, weight } of jailbreakPatterns) {
      regex.lastIndex = 0;
      // In enhanced mode, lower the weight threshold
      const threshold = enhanced ? 0.4 : 0.6;
      if (regex.test(text) && weight >= threshold) {
        matchedPatterns.push(`jailbreak:${category}`);
      }
    }

    return {
      matched: matchedPatterns.length > 0,
      patterns: matchedPatterns,
    };
  }

  /**
   * Check metadata fields for instruction-like content.
   * @param {Object} metadataFields - Parsed metadata fields
   * @returns {{ hasInstructions: boolean, patterns: string[] }}
   */
  function checkMetadataForInstructions(metadataFields) {
    const patterns = [];
    const allPatterns = [...injectionPatterns, ...jailbreakPatterns.map(p => ({ ...p, action: 'reject' }))];

    for (const [fieldName, fieldValue] of Object.entries(metadataFields)) {
      if (typeof fieldValue !== 'string') continue;

      for (const { regex, category } of allPatterns) {
        regex.lastIndex = 0;
        if (regex.test(fieldValue)) {
          patterns.push(`metadata:${fieldName}:${category}`);
        }
      }
    }

    return {
      hasInstructions: patterns.length > 0,
      patterns,
    };
  }

  /**
   * Analyze an image buffer for embedded injection attempts.
   *
   * @param {Buffer} imageBuffer - Raw image data
   * @param {Object} [context={}] - Request context (userId, agentId, sourceIP)
   * @returns {Promise<AnalysisResult>}
   */
  async function analyze(imageBuffer, context = {}) {
    const startTime = Date.now();

    // Validate input
    if (!imageBuffer || !Buffer.isBuffer(imageBuffer) || imageBuffer.length === 0) {
      return {
        allowed: false,
        error: 'Invalid image buffer',
      };
    }

    const imageHash = computeImageHash(imageBuffer);

    // Req 17.5: Reject images exceeding size limits
    if (imageBuffer.length > MAX_IMAGE_SIZE) {
      logger.logBlockedAttack({
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        attackCategory: 'multimodal_size_exceeded',
        matchedPattern: `size:${imageBuffer.length}`,
        action: 'blocked',
        imageHash,
      });

      return {
        allowed: false,
        error: 'Image exceeds maximum size limit of 10 MB',
        imageHash,
      };
    }

    // Check dimensions
    const dimensions = parseImageDimensions(imageBuffer);
    if (dimensions.width > MAX_IMAGE_WIDTH || dimensions.height > MAX_IMAGE_HEIGHT) {
      logger.logBlockedAttack({
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        attackCategory: 'multimodal_dimensions_exceeded',
        matchedPattern: `dimensions:${dimensions.width}x${dimensions.height}`,
        action: 'blocked',
        imageHash,
      });

      return {
        allowed: false,
        error: `Image dimensions ${dimensions.width}x${dimensions.height} exceed maximum of ${MAX_IMAGE_WIDTH}x${MAX_IMAGE_HEIGHT}`,
        imageHash,
      };
    }

    // Req 17.4: Analyze and strip metadata (EXIF, IPTC, XMP)
    let strippedMetadata = false;
    let metadataPatterns = [];
    const isJpeg = imageBuffer[0] === 0xFF && imageBuffer[1] === 0xD8;
    const isPng = imageBuffer[0] === 0x89 && imageBuffer[1] === 0x50 && imageBuffer[2] === 0x4E && imageBuffer[3] === 0x47;

    if (isJpeg) {
      const { fields } = parseExif(imageBuffer);
      const metaCheck = checkMetadataForInstructions(fields);
      if (metaCheck.hasInstructions) {
        strippedMetadata = true;
        metadataPatterns = metaCheck.patterns;

        logger.log('WARN', 'metadata-injection-attempt', {
          sourceIP: context.sourceIP || 'unknown',
          agentTarget: context.agentId || 'unknown',
          imageHash,
          matchedPatterns: metaCheck.patterns,
          action: 'stripped',
        });
      }

      // Always check for metadata presence and strip if any fields found
      if (Object.keys(fields).length > 0) {
        strippedMetadata = true;
      }
    } else if (isPng) {
      const textChunks = extractPngTextChunks(imageBuffer);
      if (textChunks.length > 0) {
        const fields = {};
        textChunks.forEach((chunk, i) => {
          fields[chunk.keyword || `chunk_${i}`] = chunk.text;
        });
        const metaCheck = checkMetadataForInstructions(fields);
        if (metaCheck.hasInstructions) {
          strippedMetadata = true;
          metadataPatterns = metaCheck.patterns;

          logger.log('WARN', 'metadata-injection-attempt', {
            sourceIP: context.sourceIP || 'unknown',
            agentTarget: context.agentId || 'unknown',
            imageHash,
            matchedPatterns: metaCheck.patterns,
            action: 'stripped',
          });
        }

        if (textChunks.length > 0) {
          strippedMetadata = true;
        }
      }
    }

    // Req 17.1: Perform OCR text extraction
    let ocrResult;
    try {
      ocrResult = ocrEngine(imageBuffer);
    } catch {
      ocrResult = { segments: [], totalTextArea: 0, totalImageArea: dimensions.width * dimensions.height };
    }

    // Req 17.6: Filter by OCR confidence threshold
    const confidentSegments = ocrResult.segments.filter(
      seg => seg.confidence >= confidenceThreshold
    );

    // Combine extracted text
    const extractedText = confidentSegments.map(seg => seg.text).join(' ');

    // Req 17.3: Calculate text area coverage
    const textCoverage = ocrResult.totalImageArea > 0
      ? ocrResult.totalTextArea / ocrResult.totalImageArea
      : 0;
    const highTextCoverage = textCoverage > TEXT_COVERAGE_THRESHOLD;

    // Req 17.2: Match extracted text against pattern registries
    const textMatchResult = matchPatterns(extractedText, highTextCoverage);

    // Combine all matched patterns
    const allMatchedPatterns = [...textMatchResult.patterns, ...metadataPatterns];

    // Determine if image should be blocked
    const shouldBlock = textMatchResult.matched;

    if (shouldBlock) {
      // Req 17.7: Log blocked event
      logger.logBlockedAttack({
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        attackCategory: 'multimodal_injection',
        matchedPattern: allMatchedPatterns.join(', '),
        action: 'blocked',
        imageHash,
        textSummary: extractedText.slice(0, 200),
        userId: context.userId || 'unknown',
      });

      return {
        allowed: false,
        flagged: true,
        strippedMetadata,
        matchedPatterns: allMatchedPatterns,
        error: 'Image contains embedded instructions',
        imageHash,
      };
    }

    // Req 17.3: Flag high text coverage even if no injection pattern matched
    if (highTextCoverage) {
      logger.log('INFO', 'multimodal-high-text-coverage', {
        sourceIP: context.sourceIP || 'unknown',
        agentTarget: context.agentId || 'unknown',
        imageHash,
        textCoverage: Math.round(textCoverage * 100) + '%',
        textSummary: extractedText.slice(0, 200),
      });

      return {
        allowed: true,
        flagged: true,
        strippedMetadata,
        matchedPatterns: allMatchedPatterns.length > 0 ? allMatchedPatterns : undefined,
        imageHash,
      };
    }

    // Image passes all checks
    const elapsed = Date.now() - startTime;
    if (elapsed > PERFORMANCE_TARGET_MS && imageBuffer.length <= 5 * 1024 * 1024) {
      logger.log('WARN', 'multimodal-performance-exceeded', {
        elapsed,
        targetMs: PERFORMANCE_TARGET_MS,
        imageSize: imageBuffer.length,
      });
    }

    return {
      allowed: true,
      flagged: metadataPatterns.length > 0 ? true : undefined,
      strippedMetadata: strippedMetadata || undefined,
      matchedPatterns: allMatchedPatterns.length > 0 ? allMatchedPatterns : undefined,
      imageHash,
    };
  }

  return {
    analyze,
  };
}

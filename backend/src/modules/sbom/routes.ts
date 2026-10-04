import { Router } from "express";
import multer from "multer";
import fs from "fs";

import { detectSBOMFormat } from "./formatDetector.js";
import { validateSBOM } from "./validator.js";
import { parseSBOM } from "./parser.js";
import { normalizeSBOM } from "./normalizer.js";
import { storeSBOM } from "../../services/sbomGraphService.js";


const router = Router();

const upload = multer({
  dest: "src/modules/sbom/uploads/",
});

router.post("/upload", upload.single("sbom"), async (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({
      error: "No SBOM file uploaded",
    });
  }

  try {
    // 1. Read uploaded file
    const fileContent = fs.readFileSync(req.file.path, "utf-8");

    // 2. Convert JSON text into an object
    const sbomData = JSON.parse(fileContent);

    // 3. Detect SBOM format
    const format = detectSBOMFormat(sbomData);

    // 4. Validate SBOM
    const validation = validateSBOM(sbomData, format);

    if (!validation.valid) {
      return res.status(400).json({
        message: "SBOM validation failed",
        format,
        errors: validation.errors,
      });
    }

    // 5. Parse SBOM
    const parsedSBOM = parseSBOM(sbomData, format);

    // 6. Normalize parsed SBOM
    const normalizedSBOM = normalizeSBOM(parsedSBOM);

    await storeSBOM(normalizedSBOM);

    // 7. Return result
    res.json({
      message: "SBOM uploaded successfully",

      format,

      validation: {
        valid: true,
      },

      parsedSBOM,

      normalizedSBOM,

      file: {
        originalName: req.file.originalname,
        storedName: req.file.filename,
        size: req.file.size,
        path: req.file.path,
      },
    });
  } catch (error) {
    console.error("SBOM processing error:", error);

    res.status(400).json({
      error: "Invalid JSON SBOM file",
    });
  }
});

export default router;
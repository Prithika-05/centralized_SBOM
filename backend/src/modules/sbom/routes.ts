import { Router } from "express";
import multer from "multer";
import fs from "fs";
import { detectSBOMFormat } from "./formatDetector.js";
import { validateSBOM } from "./validator.js";
import { parseSBOM } from "./parser.js";

const router = Router();

const upload = multer({
  dest: "src/modules/sbom/uploads/",
});

router.post("/upload", upload.single("sbom"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      error: "No SBOM file uploaded",
    });
  }

  try {
    const fileContent = fs.readFileSync(req.file.path, "utf-8");
    const sbomData = JSON.parse(fileContent);

    const format = detectSBOMFormat(sbomData);

    const validation = validateSBOM(sbomData, format);

    if (!validation.valid) {
      return res.status(400).json({
        message: "SBOM validation failed",
        format,
        errors: validation.errors,
      });
    }

    const parsedSBOM = parseSBOM(sbomData, format);

    res.json({
      message: "SBOM uploaded successfully",
      format,
      validation: {
        valid: true,
      },
      parsedSBOM,
      file: {
        originalName: req.file.originalname,
        storedName: req.file.filename,
        size: req.file.size,
        path: req.file.path,
      },
    });
  } catch (error) {
    res.status(400).json({
      error: "Invalid JSON SBOM file",
    });
  }
});

export default router;
import { Router } from "express";
import multer from "multer";

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

  res.json({
    message: "SBOM uploaded successfully",
    file: {
      originalName: req.file.originalname,
      storedName: req.file.filename,
      size: req.file.size,
      path: req.file.path,
    },
  });
});

export default router;
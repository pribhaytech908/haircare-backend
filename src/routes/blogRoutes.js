const express = require("express");
const { createBlog, getBlogs, deleteBlog } = require("../controllers/blogController");
const { requireAuth, adminAuth } = require("../middleware/clerkAuth");

const router = express.Router();

router.get("/", getBlogs);
router.post("/", requireAuth, adminAuth, createBlog);
router.delete("/:id", requireAuth, adminAuth, deleteBlog);

module.exports = router;

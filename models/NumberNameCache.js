const mongoose = require("mongoose");

const NumberNameCacheSchema = new mongoose.Schema({
  tenantId: { type: String, required: true },

  telegramname: { type: String, required: true }, // userId

  name: { type: String },

  chatKey: { type: String }, // 🔥 YENİ (opsiyonel)

  source: { type: String },
  updatedAt: { type: Date },
}, { timestamps: true });

NumberNameCacheSchema.index(
  { tenantId: 1, telegramname: 1 },
  { unique: true }
);

// (Opsiyonel) 90 gün sonra otomatik silinsin istersen:
// NumberNameCacheSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 90 });

module.exports = mongoose.model("NumberNameCache", NumberNameCacheSchema);

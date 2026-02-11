const mongoose = require("mongoose");

const MediaSchema = new mongoose.Schema({
  mimetype: { type: String },
  data: { type: String },
  fileName: { type: String },
  type: { type: String }
}, { _id: false });

const MessageSchema = new mongoose.Schema({
  tenantId: { type: String, index: true },
  accountId: { type: Number, index: true },

  chatKey: { type: String, index: true },

  fromType: { type: String, enum: ["customer", "agent", "admin"] },
  from: String,                 // number / extension / adminId
  to: String,                   // customer number

  body: String,

  media: MediaSchema,

  agentId: String,
  agentExtension: String,
  adminId: String,
  isActive: { type: Boolean, default: true, index: true },

  timestamp: { type: Date, default: Date.now },
}, { timestamps: true });

module.exports = mongoose.model("Message", MessageSchema);

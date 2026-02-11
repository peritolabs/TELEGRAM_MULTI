const mongoose = require("mongoose");

const TenantAgentSchema = new mongoose.Schema(
  {
    tenantId: { type: String, required: true, index: true },
    agentId:  { type: String, required: true, index: true },

    role: {
      type: String,
      enum: ["admin", "agent"],
      default: "agent",
    },

    extension: { type: String },
    userTitle: { type: String },
  },
  { timestamps: true }
);

// Aynı tenant + agent sadece 1 kez olsun
TenantAgentSchema.index({ tenantId: 1, agentId: 1 }, { unique: true });

module.exports = mongoose.model("TenantAgent", TenantAgentSchema);

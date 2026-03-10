import mongoose from 'mongoose';

const { Schema } = mongoose;

const MUTUAL_FUND_ENROLLMENT_STATUSES = {
  DRAFT: 'DRAFT',
  SUBMITTED: 'SUBMITTED',
};

const MutualFundEnrollmentSchema = new Schema(
  {
    fullName: { type: String, trim: true },
    dateOfBirth: { type: Date },
    mobileNumber: { type: String, trim: true, index: true },
    emailId: { type: String, trim: true, lowercase: true, index: true },
    panNumber: { type: String, trim: true, uppercase: true },
    city: { type: String, trim: true },
    state: { type: String, trim: true },
    pinCode: { type: String, trim: true },

    isNewToMutualFunds: { type: Boolean },
    approximateInvestmentAmount: {
      type: String,
      enum: ['5000-25000', '25000-100000', '100000_PLUS'],
      index: true,
    },
    investmentTypeInterested: {
      type: String,
      enum: ['SIP', 'LUMPSUM', 'GUIDANCE'],
      index: true,
    },
    preferredContactTime: {
      type: String,
      enum: ['MORNING', 'AFTERNOON', 'EVENING'],
      index: true,
    },

    consentToBeContacted: { type: Boolean, default: false },
    declarationDate: { type: Date },
    signatureOrDigitalConsent: { type: String, trim: true },

    status: {
      type: String,
      enum: [MUTUAL_FUND_ENROLLMENT_STATUSES.DRAFT, MUTUAL_FUND_ENROLLMENT_STATUSES.SUBMITTED],
      default: MUTUAL_FUND_ENROLLMENT_STATUSES.DRAFT,
      index: true,
    },
    submittedAt: { type: Date },

    source: { type: String, trim: true },
    ipAddress: { type: String, trim: true },
    userAgent: { type: String, trim: true },
  },
  { timestamps: true },
);

MutualFundEnrollmentSchema.index({ status: 1, createdAt: -1 });

export default mongoose.model('MutualFundEnrollment', MutualFundEnrollmentSchema);

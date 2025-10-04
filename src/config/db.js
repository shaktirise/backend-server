import mongoose from 'mongoose';

export async function connectDB(uri) {
  const fallbackLocal = 'mongodb://127.0.0.1:27017/trade_advice';
  const mongoUri = uri || process.env.MONGODB_URI || fallbackLocal;

  mongoose.set('strictQuery', true);
  if (process.env.MONGOOSE_DEBUG === '1') {
    mongoose.set('debug', true);
  }

  try {

    await mongoose.connect(mongoUri, {
      autoIndex: true,
    });

    const dbName = mongoose.connection.name;
    const redacted = mongoUri.replace(/\/\/[^@]+@/, '//<redacted>@');

    if (mongoUri === fallbackLocal && !process.env.MONGODB_URI && !uri) {
      console.warn('MONGODB_URI not set; using local MongoDB fallback.');
    }
    console.log(`MongoDB connected: db=${dbName} uri=${redacted}`);

  } catch (err) {
    const redacted = mongoUri.replace(/\/\/[^@]+@/, '//<redacted>@');
    console.error(`MongoDB connection error to uri=${redacted}`);
    throw err;
  }
}

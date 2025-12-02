import { NextResponse } from "next/server";

// Configuration
const isEnabled = true;
const expirationDate = "2025-12-30";

export async function GET() {
  const now = new Date();
  const expiry = new Date(expirationDate);
  const isValid = isEnabled && now < expiry;
  
  return NextResponse.json({ valid: isValid });
}

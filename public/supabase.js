// public/supabase.js
// Konfigurasi Supabase client — dibagi ke semua halaman

import { createClient } from 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm';

// URL dan anon key dari project Supabase Anda
const SUPABASE_URL = 'https://sdjgbrkjhguoiwouwcti.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InNkamdicmtqaGd1b2l3b3V3Y3RpIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTE1MjExNTAsImV4cCI6MjEwNzA5NzE1MH0.Sm40JEXnvbAzbA-dN-V_eCyoJz_G9_DyTAie1te55-E';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
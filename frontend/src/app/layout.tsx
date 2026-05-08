import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Link from "next/link";
import { ShieldAlert } from "lucide-react";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "PhishGuard AI",
  description: "AI-powered phishing website detection system",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={`${inter.className} min-h-screen bg-[#0a0a0f] text-gray-100 flex flex-col`}>
        <header className="border-b border-[#1f1f2e] bg-[#111116] py-4">
          <div className="container mx-auto px-4 flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2 text-xl font-bold text-primary">
              <ShieldAlert className="w-8 h-8 text-primary" />
              PhishGuard AI
            </Link>
            <nav className="flex gap-6">
              <Link href="/" className="hover:text-primary transition-colors">Scan</Link>
              <Link href="/history" className="hover:text-primary transition-colors">History</Link>
            </nav>
          </div>
        </header>
        <main className="flex-grow container mx-auto px-4 py-8">
          {children}
        </main>
        <footer className="border-t border-[#1f1f2e] bg-[#111116] py-6 text-center text-sm text-gray-500">
          <p>PhishGuard AI - Defensive Cybersecurity Tool</p>
        </footer>
      </body>
    </html>
  );
}

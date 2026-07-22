import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Sidebar from "./components/Sidebar";
import "./globals.css";
import { LanguageProvider } from "@/lib/LanguageContext";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "WebSecOps - Security Dashboard",
  description: "Advanced Security Monitoring Platform",
};

import AdminLogin from "@/components/AdminLogin";
import WelcomeModal from "@/components/WelcomeModal";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-cyber-dark text-white flex h-screen overflow-hidden`}
      >
        <LanguageProvider>
          <Sidebar />
          <main className="flex-1 relative overflow-y-auto overflow-x-hidden scrollbar-thin scrollbar-thumb-cyber-primary/10 scrollbar-track-transparent">
            {children}
          </main>
          <AdminLogin />
          <WelcomeModal />
        </LanguageProvider>
      </body>
    </html>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "license-server",
  description: "Multi-tenant software licensing & distribution console",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

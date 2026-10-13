import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "license-server — self-hosted software licensing",
    template: "%s · license-server",
  },
  description:
    "Issue, validate, and manage software licenses. Signed keys, machine binding, policies, webhooks — REST + gRPC, self-hostable.",
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

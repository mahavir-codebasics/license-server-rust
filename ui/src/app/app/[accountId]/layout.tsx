import { Shell } from "@/components/shell";

export default function AppLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: { accountId: string };
}) {
  return <Shell>{children}</Shell>;
}

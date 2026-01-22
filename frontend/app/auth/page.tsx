import { AuthForm } from "@/components/auth/auth-form";

export default function AuthPage() {
  return (
    <div className="min-h-screen">
      <AuthForm />
    </div>
  );
}

export const metadata = {
  title: "Authentication - Security Orchestrator",
  description: "Sign in or create an account to access the Security Orchestrator platform",
};

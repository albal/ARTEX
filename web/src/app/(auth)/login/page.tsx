"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  // "Agree" can only be clicked after scrolling to the bottom of the terms (including when they fit without scrolling).
  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    // Reset on open, and handle the case where the content is shorter than one screen and cannot trigger a scroll.
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    // Already signed in: go straight to the main interface (under static export there is no middleware to do this redirect).
    const token = auth.getToken();
    if (token) {
      // localStorage may still hold credentials after the cookie has been lost. Sync first, then make a fresh request,
      // so the server guard or route cache cannot send the redirect back to a login page still in the checking state.
      auth.setToken(token);
      window.location.replace("/function/tasks");
      return;
    }
    api
      .authStatus()
      .then(({ initialized }) => {
        if (!initialized) router.replace("/setup");
      })
      .catch(() => setError("Unable to connect to backend service"))
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("Please read and agree to the Usage Notice");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("ARTEX", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch {
      setError("Username or password incorrect");
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        Checking login status…
      </div>
    );
  }

  return (
    <div className="flex h-dvh">
      {/* Left panel */}
      <div className="hidden flex-col items-center justify-center bg-primary p-12 text-center lg:flex lg:w-1/3">
        <div className="relative flex items-center justify-center">
          <div className="absolute size-80 rounded-full border border-primary-foreground/10" />
          <div className="absolute size-60 rounded-full border border-primary-foreground/15" />
          <div className="absolute size-40 rounded-full border border-primary-foreground/20" />
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img src="/logo.png" alt="ARTEX" width={160} height={160} className="relative brightness-0 invert" />
        </div>
      </div>

      {/* Right panel */}
      <div className="flex w-full items-center justify-center bg-background p-8 lg:w-2/3">
        <div className="w-full max-w-md space-y-10 py-24 lg:py-32">
          <div className="space-y-4 text-center">
            <h2 className="text-2xl font-medium tracking-tight">Log in</h2>
            <p className="mx-auto max-w-xl text-muted-foreground">Welcome back, please enter your password to continue ARTEX</p>
          </div>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="username">Username</Label>
              <Input id="username" value="ARTEX" readOnly className="bg-muted text-muted-foreground" />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoFocus
                autoComplete="current-password"
              />
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="text-sm font-normal leading-relaxed text-muted-foreground">
                I have read and agree
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  Usage Notice
                </button>
              </Label>
            </div>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <Button type="submit" className="w-full" disabled={loading || !password || !agreed}>
              {loading ? "Logging in..." : "Log in"}
            </Button>
          </form>
        </div>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-2xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <ShieldCheck className="size-5" />
            </div>
            <div className="space-y-0.5">
              <DialogTitle className="text-base">ARTEX Usage notice and disclaimer</DialogTitle>
              <p className="text-xs text-muted-foreground">
                Version v1.0 · Effective date 2026-09-18 · Please read all terms below completely before logging in
              </p>
            </div>
          </DialogHeader>

          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[60vh] space-y-5 overflow-y-auto px-6 py-5 text-sm leading-relaxed text-muted-foreground"
          >
            <p className="rounded-lg border bg-muted/40 p-3 text-foreground/80">
              This 'Usage Notice and Disclaimer' ("this Statement") refers to the agreement between you and the ARTEX
              project authors and contributors regarding the use of this software. Please read carefully and fully understand all terms before using, especially the disclaimer, liability limitations, and prohibited clauses highlighted in bold or colored blocks.
              <span className="font-medium text-foreground">
                {" "}
                By downloading, installing, accessing, or using this software in any way, you acknowledge that you have read, understood, and agree to all terms of this Statement.
              </span>
            </p>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  1
                </span>
                Article 1 · Definitions and Open Source License
              </h4>
              <p className="pl-7">
                This software (ARTEX) is based on GNU Affero General Public License
                v3.0 (AGPL-3.0), an open-source license. You may freely use, copy, modify, and distribute this software under its terms; however, any derivative works (including online services provided to third parties) must also be
                released under the same AGPL-3.0 license, with full source code provided to users. The complete AGPL-3.0 terms are in the accompanying LICENSE file.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  2
                </span>
                Article 2 · Authorized Usage Scope
              </h4>
              <p className="pl-7">
                The software is intended solely for personal learning, code study, security principle exploration, and technical validation in a self-hosted isolated environment, suitable for non-offensive, non-destructive uses such as education, academic research, and code review. Unless explicitly permitted herein, you may not use the software for any other purpose.
              </p>
            </section>

            <section className="space-y-2">
              <h4 className="flex items-center gap-2 font-medium text-destructive">
                <span className="flex size-5 items-center justify-center rounded-md bg-destructive/10 text-xs font-semibold text-destructive">
                  3
                </span>
                <AlertTriangle className="size-4" />
                Article 3 · Prohibited Actions
              </h4>
              <ul className="ml-7 list-decimal space-y-1.5 rounded-lg border border-destructive/20 bg-destructive/5 p-3 pl-8 text-foreground/80 marker:text-destructive/70">
                <li>
                  Strictly prohibited to scan, probe, exploit, or attack any website, online service, or networked system owned by others or third parties (regardless of authorization or ownership);
                </li>
                <li>Strictly prohibited to use this software for real penetration testing, red-team/blue-team exercises, or production environments;</li>
                <li>Strictly prohibited to use this software for illegal intrusion, data theft, ransomware, denial-of-service (DoS/DDoS), or any destructive/criminal activity;</li>
                <li>Strictly prohibited to remove, alter, or bypass any copyright, license, or security notice in the software or its output;</li>
                <li>Strictly prohibited to engage in any conduct that violates the laws, regulations, or regulatory requirements of your country or region.</li>
              </ul>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  4
                </span>
                Article 4 · Intellectual Property
              </h4>
              <p className="pl-7">
                The copyright and related IP of this software belong to the project authors and contributors, and are granted to you under the AGPL-3.0 license. Except for rights expressly granted by the agreement, no other rights are granted, either expressly or impliedly.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  5
                </span>
                Article 5 · Data and Privacy
              </h4>
              <p className="pl-7">
                This software is a self-deployed open-source program; the authors do not operate any centralized service nor collect or upload your usage data. All data generated, processed, or accessed during use is under your control and you are responsible for its legality and security; any consequences of mishandling data are your sole responsibility.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  6
                </span>
                Article 6 · Compliance and Legal Liability
              </h4>
              <p className="pl-7">
                You must comply with all applicable laws and regulations in your country or region regarding cybersecurity, data security, personal information protection, and computer crimes (in mainland China, including but not limited to the Cybersecurity Law, Data Security Law, Personal Information Protection Law, and related judicial interpretations).
                <span className="font-medium text-foreground">
                  {" "}
                  All legal responsibilities and consequences arising from your violation of the aforementioned laws or this statement are solely your own and not attributable to the software authors or contributors.
                </span>
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  7
                </span>
                Article 7 · Disclaimer and Limitation of Liability
              </h4>
              <p className="pl-7">
                This software is provided "as-is" (AS IS) and "as-available" (AS
                AVAILABLE) without any explicit or implicit warranties, including but not limited to merchantability, fitness for a particular purpose, accuracy, or non-infringement. To the fullest extent permitted by applicable law, the authors and contributors are not liable for any direct, indirect, incidental, special, or consequential damages arising from use or inability to use the software, whether or not the use was appropriate, including but not limited to data loss, system damage, business interruption, loss of profit, or legal disputes.
              </p>
            </section>

            <section className="space-y-1.5">
              <h4 className="flex items-center gap-2 font-medium text-foreground">
                <span className="flex size-5 items-center justify-center rounded-md bg-muted text-xs font-semibold text-muted-foreground">
                  8
                </span>
                Article 8 · Amendments and Final Interpretation
              </h4>
              <p className="pl-7">
                Authors may update this statement from time to time in accordance with laws or project needs; the updated version will be released with the project and become effective upon publication. Continued use of the software constitutes acceptance of the revised terms. To the extent permitted by law, the authors hold the final right of interpretation. If any clause is deemed invalid, the remaining clauses remain effective.
              </p>
            </section>
          </div>

          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs text-muted-foreground">
              {readToEnd ? "You have viewed all terms" : "Please scroll to the bottom of the terms before confirming"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                I have read and agree to all terms
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

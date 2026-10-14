import React from 'react';
import { BookOpen, ShieldAlert, CheckCircle } from 'lucide-react';

export const HelpPage: React.FC = () => {
  return (
    <div className="space-y-6 max-w-3xl">
      <div className="bg-navy-700 border border-navy-500 rounded-xl p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <BookOpen className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-bold text-white">Anti-Phishing & Link Safety Guidance</h2>
        </div>

        <div className="space-y-4 text-sm text-slate-300">
          <div>
            <h3 className="font-bold text-slate-100 flex items-center gap-2 mb-1.5">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Common Phishing Red Flags
            </h3>
            <ul className="list-disc pl-5 space-y-1 text-slate-400 text-xs leading-relaxed">
              <li><strong>High Urgency:</strong> Messages claiming your account will be deleted or suspended in 24 hours.</li>
              <li><strong>OTP & Credential Requests:</strong> Demands to enter one-time passwords or bank PINs.</li>
              <li><strong>Typosquatted URLs:</strong> Domain names replacing characters like <code>paypa1.com</code> or <code>micros0ft.xyz</code>.</li>
              <li><strong>Unsolicited Prizes:</strong> Claims of winning lotteries or cash transfers from unknown senders.</li>
            </ul>
          </div>

          <div>
            <h3 className="font-bold text-slate-100 flex items-center gap-2 mb-1.5">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              Immediate Response Steps
            </h3>
            <ol className="list-decimal pl-5 space-y-1 text-slate-400 text-xs leading-relaxed">
              <li>Never click suspicious links or download unverified attachments.</li>
              <li>If you already entered your password on a suspicious link, immediately change your password on the official website.</li>
              <li>Report suspicious messages to your IT support or bank official helpline.</li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
};

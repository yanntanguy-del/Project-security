"use client";

import Link from "next/link";

export default function Home() {
  return (
    <main className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-violet-950 via-black to-purple-950 text-white">
      <div className="bg-black/60 rounded-2xl shadow-xl p-10 max-w-xl w-full flex flex-col items-center">
        <div className="flex items-center gap-3 mb-4">
          <span className="text-4xl">🛡️</span>
          <span className="text-2xl font-bold bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent">Security Scanner</span>
        </div>
        <h1 className="text-3xl font-bold mb-2 text-center">Téléchargez l'application de sécurité</h1>
        <p className="text-lg text-gray-300 mb-6 text-center">
          Cette application n'est pas utilisable en ligne.<br />
          Pour analyser et sécuriser votre ordinateur, <b>téléchargez l'application</b> sur GitHub.
        </p>
        <Link href="https://github.com/yanntanguy-del/Project-security" target="_blank" className="inline-block px-8 py-3 rounded-xl bg-gradient-to-r from-violet-500 to-cyan-500 text-white font-semibold text-lg shadow-lg hover:scale-105 transition mb-2">
          Accéder au téléchargement GitHub
        </Link>
        <p className="text-sm text-gray-400 mt-2 text-center">
          Vous serez redirigé vers la page GitHub pour installer l'application sur Windows, macOS ou Linux.<br />
          <span className="text-yellow-400">Aucune analyse n'est possible depuis le navigateur.</span>
        </p>
        <div className="mt-8 text-xs text-gray-500 text-center">
          Version 0.1.0 &mdash; © 2025 Security Scanner<br />
          <span className="text-gray-400">Développé par yanntanguy-del</span>
        </div>
      </div>
    </main>
  );
}

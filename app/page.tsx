"use client";



import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function Home() {
  return (
    <main className="min-h-screen w-full bg-gradient-to-br from-[#12092b] via-[#18102e] to-[#0a0612] text-white flex flex-col items-center py-12 px-2">
      {/* Header */}
      <div className="flex flex-col items-center mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-[#2d225a] rounded-2xl p-3 shadow-2xl shadow-violet-900/40">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#6c47ff"/><path d="M12 7l4 2v2c0 2.5-1.5 4.5-4 6-2.5-1.5-4-3.5-4-6V9l4-2z" fill="#fff"/></svg>
          </div>
          <div className="flex flex-col">
            <span className="text-3xl font-extrabold bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent drop-shadow-lg">Security Scanner</span>
            <span className="text-xs text-gray-400 font-medium">Version 0.1.0</span>
          </div>
        </div>
      </div>

      {/* Hero Section */}
      <section className="w-full max-w-2xl rounded-3xl p-12 flex flex-col items-center mb-16">
        <h1 className="text-5xl font-extrabold text-center mb-4 leading-tight drop-shadow-xl">
          Analysez et <span className="bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent">sécurisez</span><br />
          votre système
        </h1>
        <p className="text-lg text-gray-300 mb-8 text-center max-w-xl">
          Security Scanner est un outil gratuit qui analyse votre ordinateur pour détecter les vulnérabilités et vous aide à appliquer les meilleures pratiques de sécurité.
        </p>
        <Button asChild size="lg" className="px-10 py-4 text-lg font-bold rounded-2xl bg-gradient-to-r from-violet-500 to-cyan-500 shadow-xl shadow-cyan-500/20 hover:scale-105 transition-all focus:ring-2 focus:ring-cyan-400">
          <Link href="https://github.com/yanntanguy-del/Project-security" target="_blank">
            <svg width="22" height="22" fill="none" viewBox="0 0 24 24" className="mr-2"><path d="M14 3v2h3.59L7 15.59 8.41 17 19 6.41V10h2V3z" fill="#fff"/></svg>
            Accéder au téléchargement
          </Link>
        </Button>
        <p className="text-sm text-gray-400 mt-4 text-center">
          Vous serez redirigé vers GitHub<br />
          <span className="text-yellow-400">Vous serez redirigé vers GitHub pour télécharger l’application.</span>
        </p>
      </section>

      {/* Qu'est-ce que Security Scanner ? */}
      <section className="w-full max-w-3xl bg-[#1a1033]/90 rounded-2xl shadow-lg p-8 mb-8 border border-violet-900/30">
        <h2 className="text-2xl font-bold mb-4 text-center">Qu'est-ce que Security Scanner&nbsp;?</h2>
        <p className="mb-2"><span className="font-bold">Security Scanner</span> est une application qui analyse automatiquement les paramètres de sécurité de votre ordinateur. Elle vérifie plus de 100 configurations différentes&nbsp;: pare-feu, antivirus, politiques de mot de passe, et bien d'autres.</p>
        <p className="mb-2">L'application génère un <span className="font-bold">rapport détaillé</span> avec des codes couleur&nbsp;: <span className="text-green-400 font-bold">vert</span> pour ce qui est conforme, <span className="text-red-400 font-bold">rouge</span> pour ce qui nécessite attention, et <span className="text-yellow-400 font-bold">jaune</span> pour ce qui n'a pas pu être vérifié.</p>
        <p>Pour chaque problème détecté, vous recevez des <span className="font-bold">instructions claires</span> pour corriger les vulnérabilités. L'interface est entièrement en français et conçue pour être compréhensible, même sans connaissances techniques.</p>
      </section>

      {/* Comment obtenir l'application ? */}
      <section className="w-full max-w-3xl bg-[#23204a]/90 rounded-2xl shadow-lg p-6 mb-8 border border-violet-900/30">
        <div className="flex items-center gap-3 mb-2">
          <div className="bg-blue-600 rounded-full p-2"><svg width="20" height="20" fill="none" viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z" fill="#fff"/></svg></div>
          <span className="font-bold text-lg">Comment obtenir l'application&nbsp;?</span>
        </div>
        <p className="text-gray-300">En cliquant sur le bouton ci-dessus, vous serez redirigé vers la page GitHub du projet. L'application n'est pas téléchargée directement depuis ce site.</p>
      </section>

      {/* Comment installer l'application ? */}
      <section className="w-full max-w-3xl bg-[#1a1033]/90 rounded-2xl shadow-lg p-8 mb-8 border border-violet-900/30">
        <h2 className="text-3xl font-extrabold mb-8 text-center">Comment installer l'application&nbsp;?</h2>
        <ol className="space-y-8">
          <li className="flex items-start gap-6">
            <div className="flex-shrink-0 w-14 h-14 rounded-full bg-gradient-to-br from-violet-500 to-violet-700 flex items-center justify-center text-2xl font-bold shadow-lg text-white">1</div>
            <div>
              <span className="font-bold text-lg">Accédez à GitHub</span><br />
              <span className="text-gray-300 text-base">Cliquez sur le bouton "Accéder au téléchargement" ci-dessus. Vous serez redirigé vers la page GitHub du projet.</span>
            </div>
          </li>
          <li className="flex items-start gap-6">
            <div className="flex-shrink-0 w-14 h-14 rounded-full bg-gradient-to-br from-violet-500 to-violet-700 flex items-center justify-center text-2xl font-bold shadow-lg text-white">2</div>
            <div>
              <span className="font-bold text-lg">Téléchargez le fichier ZIP</span><br />
              <span className="text-gray-300 text-base">Sur la page GitHub, cliquez sur le bouton vert <b>"Code"</b> puis sélectionnez <b>"Download ZIP"</b> pour télécharger l'archive contenant l'application.</span>
            </div>
          </li>
          <li className="flex items-start gap-6">
            <div className="flex-shrink-0 w-14 h-14 rounded-full bg-gradient-to-br from-violet-500 to-violet-700 flex items-center justify-center text-2xl font-bold shadow-lg text-white">3</div>
            <div>
              <span className="font-bold text-lg">Extrayez l'archive</span><br />
              <span className="text-gray-300 text-base">Une fois le fichier ZIP téléchargé, faites un clic droit dessus et sélectionnez <b>"Extraire tout..."</b> pour décompresser les fichiers dans un dossier de votre choix.</span>
            </div>
          </li>
          <li className="flex items-start gap-6">
            <div className="flex-shrink-0 w-14 h-14 rounded-full bg-gradient-to-br from-violet-500 to-violet-700 flex items-center justify-center text-2xl font-bold shadow-lg text-white">4</div>
            <div>
              <span className="font-bold text-lg">Lancez l'application</span><br />
              <span className="text-gray-300 text-base">Ouvrez le dossier extrait et double-cliquez sur le fichier exécutable <b>Security Scanner.exe</b> pour démarrer l'application.</span>
			</div>
		  </li>
		</ol>
	  </section>

      {/* Footer */}
      <footer className="mt-8 text-xs text-gray-500 text-center">
        Version 0.1.0 &mdash; © 2025 Security Scanner<br />
        <span className="text-gray-400">Développé par yanntanguy-del</span>
      </footer>
    </main>
  );
}

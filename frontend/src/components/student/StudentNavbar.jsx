import plvlogo from "../../assets/plvlogo.png";

const StudentNavbar = ({ onLogout, onOpenSettings }) => {
  return (
    <header
      className="w-full border-b-2 border-yellow-400 bg-[#001b55] shadow-sm"
      style={{ backgroundImage: "linear-gradient(118deg, transparent 0 48%, rgba(10,48,122,.72) 48.2% 62%, transparent 62.2%), linear-gradient(142deg, transparent 0 68%, rgba(0,43,112,.85) 68.2% 83%, transparent 83.2%), linear-gradient(105deg, #00113f 0%, #002469 54%, #001748 100%)" }}
    >
      <div className="flex w-full items-center justify-between px-6 py-4">
        {/* Left */}
        <div className="flex items-center gap-3">
          <button type="button" onClick={onOpenSettings} aria-label="Profile settings" title="Profile settings" className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/30 text-white transition hover:border-yellow-400 hover:text-yellow-300">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="h-5 w-5"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1z"/></svg>
          </button>
          <div className="flex h-11 w-11 items-center justify-center rounded-full bg-white/10">
            <img
              src={plvlogo}
              alt="PLV Logo"
              className="h-10 w-10 object-contain"
            />
          </div>

          <div className="leading-tight">
            <p className="text-sm text-white/80">Student Portal</p>
            <h1 className="text-xl font-bold text-white">
            Welcome, PLVian!
            </h1>
          </div>
        </div>

        {/* Right */}
        <div className="flex items-center gap-3">
          <button
            onClick={onLogout}
            className="rounded-xl border border-yellow-400 bg-transparent px-5 py-2 text-sm font-semibold text-yellow-400 transition hover:bg-yellow-400 hover:text-[#003366]"
          >
            Logout
          </button>
        </div>
      </div>
    </header>
  );
};

export default StudentNavbar;

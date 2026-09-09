import React from "react";
import plvlogo from "../../assets/plvlogo.png";

function RegistrarHeader({ registrarData, onLogout }) {
  return (
    <header
      className="w-full border-b-2 border-yellow-400 bg-[#001b55] shadow-sm"
      style={{
        backgroundImage: [
          "linear-gradient(118deg, transparent 0 48%, rgba(10, 48, 122, 0.72) 48.2% 62%, transparent 62.2%)",
          "linear-gradient(142deg, transparent 0 68%, rgba(0, 43, 112, 0.85) 68.2% 83%, transparent 83.2%)",
          "linear-gradient(105deg, #00113f 0%, #002469 54%, #001748 100%)",
        ].join(", "),
      }}
    >
      <div className="flex w-full items-center justify-between px-6 py-4">
        {/* Left */}
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-full bg-white/10">
            <img
              src={plvlogo}
              alt="PLV Logo"
              className="h-10 w-10 object-contain"
            />
          </div>

          <div className="leading-tight">
            <p className="text-sm text-white/80">Registrar Portal</p>
            <h1 className="text-xl font-bold text-white">Welcome, Registrar</h1>
          </div>
        </div>

        {/* Right */}
        <div className="flex items-center gap-3">
          <div className="hidden rounded-xl bg-white/10 px-4 py-2 text-right md:block">
            <p className="text-xs text-white/70">Semester</p>
            <p className="text-sm font-semibold text-white">
              {registrarData?.semester || "2nd Semester"}
            </p>
          </div>

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
}

export default RegistrarHeader;

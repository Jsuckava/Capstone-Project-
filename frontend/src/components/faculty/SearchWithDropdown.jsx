import React, { useState, useRef, useEffect } from "react";
import { programs as availablePrograms } from "../../data/registrarData";

const programs = ["All Programs", ...availablePrograms];

const SearchWithDropdown = ({ setSelectedProgram }) => {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const wrapperRef = useRef(null);

  useEffect(() => {
    if (!open) return;

    const handleOutsideClick = (event) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target)) {
        setOpen(false);
      }
    };

    document.addEventListener("click", handleOutsideClick);

    return () => {
      document.removeEventListener("click", handleOutsideClick);
    };
  }, [open]);

  const filteredPrograms = programs.filter((program) =>
    program.toLowerCase().includes(query.toLowerCase())
  );

  const handleSelect = (program) => {
    const value = program === "All Programs" ? "" : program;
    setSelectedProgram(value);
    setQuery(value);
    setOpen(false);
  };

  return (
    <div ref={wrapperRef} className="relative w-full">
      <input
        type="text"
        value={query}
        placeholder="Search program..."
        onFocus={() => setOpen(true)}
        onChange={(e) => {
          setQuery(e.target.value);
          setSelectedProgram(e.target.value);
          setOpen(true);
        }}
        className="h-12 w-full rounded-xl border border-slate-300 bg-white px-4 pr-10 text-sm shadow-sm focus:outline-none focus:ring-2 focus:ring-[#003366]"
      />

      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500"
      >
        ▼
      </button>

      {open && (
        <div className="absolute z-50 mt-2 max-h-60 w-full overflow-y-auto rounded-xl border border-slate-200 bg-white shadow-lg">
          {filteredPrograms.length > 0 ? (
            filteredPrograms.map((program) => (
              <div
                key={program}
                onClick={() => handleSelect(program)}
                className="cursor-pointer px-4 py-3 text-sm hover:bg-slate-100"
              >
                {program}
              </div>
            ))
          ) : (
            <div className="px-4 py-3 text-sm text-slate-400">
              No result
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SearchWithDropdown;

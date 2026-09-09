import React, { useState } from "react";
import plvbg from "../assets/plvbg.png";
import plvlogo from "../assets/plvlogo.png";

const LoginPage = ({ onLogin }) => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleSubmit = (e) => {
  e.preventDefault();

  if (
    email !== "faculty@gmail.com" &&
    email !== "student@gmail.com" &&
    email !== "chairperson@gmail.com" &&
    email !== "registrar@gmail.com"
  ) {
    alert("Unauthorized email address.");
    return;
  }

  onLogin(email);
};

  return (
    <div className="flex h-screen">
      <div
        className="hidden bg-cover bg-center md:block md:w-1/2"
        style={{ backgroundImage: `url(${plvbg})` }}
      />

      <div className="flex w-full items-center justify-center bg-white md:w-1/2">
        <div className="w-full max-w-sm px-6">
          <img
            src={plvlogo}
            alt="PLV Logo"
            className="mx-auto mb-4 w-24"
          />

          <h2 className="mb-6 text-center text-2xl font-semibold text-[#003366]">
            Welcome
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="mb-1 block text-sm text-gray-700">Email</label>
              <input
                type="email"
                placeholder="faculty@gmail.com / student@gmail.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full rounded-lg border p-3 focus:outline-none focus:ring-2 focus:ring-blue-900"
                required
              />
            </div>

            <div>
              <label className="mb-1 block text-sm text-gray-700">
                Password
              </label>
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border p-3 focus:outline-none focus:ring-2 focus:ring-blue-900"
                required
              />
            </div>

            <button
              type="submit"
              className="w-full rounded-lg bg-[#003366] py-3 font-bold text-white transition hover:bg-[#002244]"
            >
              Sign In
            </button>
          </form>

          <p className="mt-4 text-center text-sm text-gray-500">
            Forgot Password?
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
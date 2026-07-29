// Password generator: characters or passphrase, CSPRNG throughout.
// Rejection sampling keeps character draws uniform; passphrases draw from
// the same 2048-word list as Secret Phrases (11 bits/word).

import { WORDLIST } from "./wordlist";

export type GeneratorOptions = {
  mode: "characters" | "passphrase";
  length: number; // characters mode
  words: number; // passphrase mode
  letters: boolean;
  digits: boolean;
  symbols: boolean;
};

export const DEFAULT_GENERATOR: GeneratorOptions = {
  mode: "characters",
  length: 20,
  words: 5,
  letters: true,
  digits: true,
  symbols: true,
};

const LOWER = "abcdefghijkmnopqrstuvwxyz"; // no l
const UPPER = "ABCDEFGHJKMNPQRSTUVWXYZ"; // no I, L, O
const DIGITS = "23456789"; // no 0, 1
const SYMBOLS = "!#$%&*+-=?@^_~";

// The three toggleable character classes. Order fixes how they read in the
// UI and how a generated password is coloured back into classes; the UI is
// the single place that decides which token tints which class.
export type CharacterClass = "letters" | "digits" | "symbols";

const CLASS_ALPHABETS: Record<CharacterClass, string> = {
  letters: LOWER + UPPER,
  digits: DIGITS,
  symbols: SYMBOLS,
};

// enabledClasses is the source of truth for "what can this password contain".
// Turning everything off would leave nothing to draw from, so letters stand
// in — the UI also prevents unchecking the last box, making this the belt to
// that braces.
export function enabledClasses(options: GeneratorOptions): CharacterClass[] {
  const active = (["letters", "digits", "symbols"] as const).filter((name) => options[name]);
  return active.length ? [...active] : ["letters"];
}

// classify maps a character back to the class that produced it, so the
// preview can colour each one. Unknown characters (a passphrase separator)
// report as symbols, which is what they look like.
export function classify(char: string): CharacterClass {
  if (CLASS_ALPHABETS.digits.includes(char)) return "digits";
  if (/[a-z]/i.test(char)) return "letters";
  return "symbols";
}

function uniformInt(maxExclusive: number): number {
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % maxExclusive;
  }
}

export function generatePassword(options: GeneratorOptions): string {
  if (options.mode === "passphrase") {
    const words: string[] = [];
    for (let i = 0; i < Math.max(3, options.words); i++) {
      words.push(WORDLIST[uniformInt(WORDLIST.length)]);
    }
    return words.join("-");
  }

  const classes = enabledClasses(options);
  const alphabet = classes.map((name) => CLASS_ALPHABETS[name]).join("");
  // One guaranteed character per enabled class. Letters guarantee both cases,
  // so "letters only" still can't come back all-lowercase.
  const required: string[] = classes.flatMap((name) =>
    name === "letters" ? [pick(LOWER), pick(UPPER)] : [pick(CLASS_ALPHABETS[name])],
  );

  const length = Math.max(8, options.length);
  const chars: string[] = [];
  for (let i = 0; i < length - required.length; i++) chars.push(alphabet[uniformInt(alphabet.length)]);
  // Weave the guaranteed classes in at random positions so "at least one of
  // each" never means a predictable prefix.
  for (const ch of required) chars.splice(uniformInt(chars.length + 1), 0, ch);
  return chars.join("");
}

function pick(alphabet: string): string {
  return alphabet[uniformInt(alphabet.length)];
}

// entropyBits estimates strength for the meter under the generator.
export function entropyBits(options: GeneratorOptions): number {
  if (options.mode === "passphrase") return Math.round(Math.max(3, options.words) * Math.log2(WORDLIST.length));
  const alphabet = enabledClasses(options).reduce((total, name) => total + CLASS_ALPHABETS[name].length, 0);
  return Math.round(Math.max(8, options.length) * Math.log2(alphabet));
}

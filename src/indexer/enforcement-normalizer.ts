/**
 * Asset Enforcement & Clawback Event Normalizer — Issue #174
 *
 * Parses raw Soroban events for RWA enforcement actions (clawback, freeze,
 * seize, set_authorized) and produces rich human-readable summaries.
 *
 * Integrates with sep41-parser for the base clawback event and extends it
 * with RWA-specific enforcement semantics.
 */

import { xdr, scValToNative } from '@stellar/stellar-sdk';
import { decodeTypedArgs, formatAmount } from './args-decoder';
import { parseSep41Event } from './sep41-parser';
import { trackRwaClawback } from './rwa-compliance-tracker';
import type { AbiParam } from './registry';

// ─── Enforcement event definitions ───────────────────────────────────────────

export type EnforcementAction =
  | 'clawback'
  | 'freeze'
  | 'seize'
  | 'set_authorized'
  | 'set_admin';

interface EnforcementEventDef {
  symbol: string;
  action: EnforcementAction;
  topicParams: AbiParam[];
  dataParam: AbiParam;
  humanTemplate: string;
}

const ENFORCEMENT_EVENTS: Record<string, EnforcementEventDef> = {
  clawback: {
    symbol: 'clawback',
    action: 'clawback',
    topicParams: [
      { name: 'admin', type: 'address' },
      { name: 'from', type: 'address' },
    ],
    dataParam: { name: 'amount', type: 'i128' },
    humanTemplate:
      'Issuer executed a regulatory clawback of {amount} {token} from address {from}',
  },
  freeze: {
    symbol: 'freeze',
    action: 'freeze',
    topicParams: [
      { name: 'admin', type: 'address' },
      { name: 'account', type: 'address' },
    ],
    dataParam: { name: 'frozen', type: 'bool' },
    humanTemplate:
      'Issuer {frozen} account {account} on {token} contract',
  },
  seize: {
    symbol: 'seize',
    action: 'seize',
    topicParams: [
      { name: 'admin', type: 'address' },
      { name: 'from', type: 'address' },
    ],
    dataParam: { name: 'amount', type: 'i128' },
    humanTemplate:
      'Regulatory seizure of {amount} {token} from address {from} by issuer',
  },
  set_authorized: {
    symbol: 'set_authorized',
    action: 'set_authorized',
    topicParams: [
      { name: 'admin', type: 'address' },
      { name: 'account', type: 'address' },
    ],
    dataParam: { name: 'authorized', type: 'bool' },
    humanTemplate:
      'Issuer {authorized} address {account} to hold {token}',
  },
};

const ENFORCEMENT_SYMBOLS = new Set(Object.keys(ENFORCEMENT_EVENTS));

export function isEnforcementEvent(symbol: string): boolean {
  return ENFORCEMENT_SYMBOLS.has(symbol);
}

// ─── Parsed result ────────────────────────────────────────────────────────────

export interface EnforcementParsedEvent {
  symbol: string;
  action: EnforcementAction;
  fields: Record<string, { raw: unknown; formatted: string }>;
  humanReadable: string;
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/**
 * Parse a raw Soroban enforcement event from base64-encoded XDR topics/data.
 *
 * Handles both the standard SEP-41 clawback event (via sep41-parser) and
 * RWA-specific enforcement events (freeze, seize, set_authorized).
 *
 * Returns null if the event is not a known enforcement event.
 */
export function parseEnforcementEvent(
  topics: string[],
  data: string,
  decimals = 7,
  tokenSymbol = '',
): EnforcementParsedEvent | null {
  if (topics.length === 0) return null;

  let symbol: string;
  try {
    const symbolVal = xdr.ScVal.fromXDR(topics[0], 'base64');
    symbol = symbolVal.switch().name === 'scvSymbol'
      ? symbolVal.sym().toString()
      : String(scValToNative(symbolVal));
  } catch {
    return null;
  }

  // Delegate standard SEP-41 clawback to sep41-parser, then re-wrap
  if (symbol === 'clawback') {
    const sep41 = parseSep41Event(topics, data, decimals, tokenSymbol);
    if (!sep41) return null;

    const admin = sep41.fields.admin ?? { raw: '', formatted: '' };
    const from  = sep41.fields.from  ?? { raw: '', formatted: '' };
    const amount = sep41.fields.amount ?? { raw: 0n, formatted: '0' };

    const humanReadable =
      `Issuer executed a regulatory clawback of ${amount.formatted}` +
      (tokenSymbol ? ` ${tokenSymbol}` : '') +
      ` from address ${from.formatted}`;

    return {
      symbol: 'clawback',
      action: 'clawback',
      fields: sep41.fields,
      humanReadable,
    };
  }

  const def = ENFORCEMENT_EVENTS[symbol];
  if (!def) return null;

  const fields: Record<string, { raw: unknown; formatted: string }> = {};

  // Decode topic params (topics[1], topics[2], …)
  for (let i = 0; i < def.topicParams.length; i++) {
    const topicXdr = topics[i + 1];
    if (!topicXdr) continue;
    try {
      const val = xdr.ScVal.fromXDR(topicXdr, 'base64');
      const [decoded] = Object.values(decodeTypedArgs([def.topicParams[i]], [val], decimals));
      if (decoded) fields[def.topicParams[i].name] = decoded;
    } catch {
      fields[def.topicParams[i].name] = { raw: topicXdr, formatted: topicXdr };
    }
  }

  // Decode data field
  try {
    const dataVal = xdr.ScVal.fromXDR(data, 'base64');
    const [decoded] = Object.values(decodeTypedArgs([def.dataParam], [dataVal], decimals));
    if (decoded) fields[def.dataParam.name] = decoded;
  } catch {
    fields[def.dataParam.name] = { raw: data, formatted: data };
  }

  const humanReadable = renderEnforcementTemplate(def.humanTemplate, fields, tokenSymbol);

  return { symbol, action: def.action, fields, humanReadable };
}

// ─── Template renderer ────────────────────────────────────────────────────────

function renderEnforcementTemplate(
  template: string,
  fields: Record<string, { raw: unknown; formatted: string }>,
  tokenSymbol: string,
): string {
  return template.replace(/\{(\w+)\}/g, (_match, key: string) => {
    if (key === 'token') return tokenSymbol;

    const entry = fields[key];
    if (!entry) return '';

    // Boolean fields: render as human-friendly verbs
    if (key === 'frozen') {
      return entry.raw === true ? 'froze' : 'unfroze';
    }
    if (key === 'authorized') {
      return entry.raw === true ? 'authorized' : 'deauthorized';
    }

    return entry.formatted;
  });
}

// ─── Processor ───────────────────────────────────────────────────────────────

export interface RawEnforcementEvent {
  topics: string[];
  data: string;
  contractAddress: string;
  transactionHash: string;
  ledgerSequence: number;
  ledgerCloseTime: Date;
  decimals?: number;
  tokenSymbol?: string;
}

/**
 * Process a raw Soroban event, persist it via rwa-compliance-tracker if it is
 * a clawback, and return the normalized result.
 *
 * Returns null for non-enforcement events.
 */
export async function processEnforcementEvent(
  event: RawEnforcementEvent,
): Promise<EnforcementParsedEvent | null> {
  const parsed = parseEnforcementEvent(
    event.topics,
    event.data,
    event.decimals ?? 7,
    event.tokenSymbol ?? '',
  );

  if (!parsed) return null;

  // Persist clawback events via the existing compliance tracker
  if (parsed.action === 'clawback') {
    const issuer  = String(parsed.fields.admin?.formatted ?? '');
    const target  = String(parsed.fields.from?.formatted  ?? '');
    const amount  = String(parsed.fields.amount?.formatted ?? '0');

    await trackRwaClawback(
      event.transactionHash,
      event.ledgerSequence,
      event.ledgerCloseTime,
      event.contractAddress,
      issuer,
      target,
      amount,
      'regulatory enforcement',
    );
  }

  return parsed;
}

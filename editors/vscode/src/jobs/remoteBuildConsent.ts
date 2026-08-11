import type {
  RemoteBuildConsent,
  RemoteBuildPreviewResponse
} from "../cli/protocol.js";

export async function submitAfterRemoteBuildConsent<T>(
  preview: RemoteBuildPreviewResponse,
  confirm: (preview: RemoteBuildPreviewResponse) => Promise<boolean>,
  approve: (preview: RemoteBuildPreviewResponse) => RemoteBuildConsent,
  submit: (consent: RemoteBuildConsent) => Promise<T>
): Promise<T | undefined> {
  if (!await confirm(preview)) {
    return undefined;
  }
  return await submit(approve(preview));
}

export function remoteBuildPreviewDetail(preview: RemoteBuildPreviewResponse): string {
  return [
    `Provider: ${preview.provider}`,
    `Files: ${preview.source.file_count}`,
    `Bytes: ${preview.source.total_bytes}`,
    `Preview SHA-256: ${preview.preview_sha256}`,
    ...preview.effects.map((effect) => `- ${displayConsentText(effect)}`)
  ].join("\n");
}

function displayConsentText(value: string): string {
  return value.replaceAll(/[\r\n\t\u2028\u2029]+/gu, " ").trim();
}

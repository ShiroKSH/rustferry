import * as path from "node:path";

export type ArtifactProjectRoot = {
  readonly root: {
    readonly scheme: string;
    readonly fsPath: string;
  };
};

export function generatedArtifactRoot(project: ArtifactProjectRoot): string {
  return path.join(project.root.fsPath, "target", "ferry");
}

export function artifactPathWithinGeneratedRoot(
  project: ArtifactProjectRoot,
  artifactPath: string
): boolean {
  if (project.root.scheme !== "file" || !path.isAbsolute(artifactPath)) {
    return false;
  }
  const target = path.resolve(generatedArtifactRoot(project));
  const artifact = path.resolve(artifactPath);
  const relative = path.relative(target, artifact);
  return relative.length > 0 && !relative.startsWith("..") && !path.isAbsolute(relative);
}

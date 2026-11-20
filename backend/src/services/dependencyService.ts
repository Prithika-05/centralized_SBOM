import { neo4jDriver } from "../config/neo4j.js";

export interface DependencyResult {
  componentId: string;
  dependencies: {
    id: string;
    name: string;
    version: string;
  }[];
}

export interface TransitiveDependencyResult {
  componentId: string;
  dependencies: {
    id: string;
    name: string;
    version: string;
  }[];
}

export async function getDirectDependencies(
  componentId: string,
  sbomId: string
): Promise<DependencyResult> {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (source:Component {id: $componentId})
            -[r:DEPENDS_ON {sbomId: $sbomId}]->
            (dependency:Component)

      RETURN
        dependency.id AS id,
        dependency.name AS name,
        dependency.version AS version
      `,
      {
        componentId,
        sbomId,
      }
    );

    return {
      componentId,
      dependencies: result.records.map((record) => ({
        id: record.get("id"),
        name: record.get("name"),
        version: record.get("version"),
      })),
    };
  } finally {
    await session.close();
  }
}


export async function getTransitiveDependencies(
  componentId: string,
  sbomId: string
): Promise<TransitiveDependencyResult> {
  const session = neo4jDriver.session();

  try {
    const result = await session.run(
      `
      MATCH (source:Component {id: $componentId})
            -[r:DEPENDS_ON*1..]-> 
            (dependency:Component)
      WHERE ALL(rel IN r WHERE rel.sbomId = $sbomId)

      RETURN DISTINCT
        dependency.id AS id,
        dependency.name AS name,
        dependency.version AS version
      `,
      {
        componentId,
        sbomId,
      }
    );

    return {
      componentId,
      dependencies: result.records.map((record) => ({
        id: record.get("id"),
        name: record.get("name"),
        version: record.get("version"),
      })),
    };
  } finally {
    await session.close();
  }
}



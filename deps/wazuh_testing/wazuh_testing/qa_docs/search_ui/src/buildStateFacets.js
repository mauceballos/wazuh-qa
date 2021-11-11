function getValueFacet(aggregations, fieldName) {
  if (
    aggregations &&
    aggregations[fieldName] &&
    aggregations[fieldName].buckets &&
    aggregations[fieldName].buckets.length > 0
  ) {
    return [
      {
        field: fieldName,
        type: "value",
        data: aggregations[fieldName].buckets.map(bucket => ({
          // Boolean values and date values require using `key_as_string`
          value: bucket.key_as_string || bucket.key,
          count: bucket.doc_count
        }))
      }
    ];
  }
}

export default function buildStateFacets(aggregations) {
  const brief = getValueFacet(aggregations, "brief");
  const name = getValueFacet(aggregations, "name");
  const tiers = getValueFacet(aggregations, "tiers");
  const os_platform = getValueFacet(aggregations, "os_platform");
  const modules = getValueFacet(aggregations, "modules");
  const daemons = getValueFacet(aggregations, "daemons");
  const components = getValueFacet(aggregations, "components");

  const facets = {
    ...(brief && { brief }),
    ...(name && { name }),
    ...(tiers && {tiers}),
    ...(os_platform && {os_platform}),
    ...(modules && {modules}),
    ...(daemons && {daemons}),
    ...(components && {components})
  };

  if (Object.keys(facets).length > 0) {
    return facets;
  }
}

/**
 * Parses attendance device response text into structured records.
 * Format: found=N\r\nrecords[i].FieldName=value\r\n...
 * @param {string} text - Raw response (e.g. from device API)
 * @returns {{ found: number, records: Array<Record<string, string|number>> }}
 */
export const parseRecords = (text) => {
  if (!text || typeof text !== "string") {
    return { found: 0, records: [] };
  }

  const lines = text.split(/\r\n|\n/).filter(Boolean);
  let found = 0;
  const byIndex = Object.create(null);

  const foundMatch = text.match(/^found=(\d+)/m);
  if (foundMatch) {
    found = parseInt(foundMatch[1], 10);
  }

  const recordRegex = /^records\[(\d+)\]\.([^=]+)=(.*)$/;
  for (const line of lines) {
    const m = line.trim().match(recordRegex);
    if (!m) continue;
    const [, indexStr, field, value] = m;
    const index = parseInt(indexStr, 10);
    if (!byIndex[index]) byIndex[index] = {};
    byIndex[index][field] = value;
  }

  const maxIndex = Object.keys(byIndex).length ? Math.max(...Object.keys(byIndex).map(Number)) : -1;
  const records = [];
  for (let i = 0; i <= maxIndex; i++) {
    if (byIndex[i]) records.push(byIndex[i]);
  }

  return { found, records };
}

function groupByUser(records) {
    const grouped = {};
  
    records.forEach(record => {
      const userId = record.UserID;
      const createTime = new Date(record.CreateTime);
  
      if (!grouped[userId]) {
        grouped[userId] = {
          UserID: userId,
          CardName: record.CardName,
          EntryTime: createTime,
          ExitTime: createTime
        };
      } else {
        if (createTime < grouped[userId].EntryTime) {
          grouped[userId].EntryTime = createTime;
        }
        if (createTime > grouped[userId].ExitTime) {
          grouped[userId].ExitTime = createTime;
        }
      }
    });
  
    // Convert EntryTime and ExitTime back to ISO strings
    return Object.values(grouped).map(u => ({
      ...u,
      EntryTime: u.EntryTime.toISOString(),
      ExitTime: u.ExitTime.toISOString()
    }));
  }
  
  // Example usage:
  const result = groupByUser(records);
  console.log(result);
  
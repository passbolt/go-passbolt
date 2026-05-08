package api

type ForeignModelTypes string

const (
	ForeignModelTypesResource ForeignModelTypes = "Resource"
	ForeignModelTypesSecret   ForeignModelTypes = "Secret"
	ForeignModelTypesFolder                     = "Folder"
	ForeignModelTypesComment                    = "Comment"
	ForeignModelTypesTag                        = "Tag"
)

func (s ForeignModelTypes) IsValid() bool {
	switch s {
	case ForeignModelTypesResource, ForeignModelTypesSecret, ForeignModelTypesFolder, ForeignModelTypesComment, ForeignModelTypesTag:
		return true
	}
	return false
}
